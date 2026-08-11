import { createHmac, randomUUID, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import type { StateStore } from './state-store.js';

const scrypt = promisify(scryptCb);
export type Claims = Record<string, string | boolean | number>;
export type Credential = { id: string; userId: string; type: string; claims: Claims; issuer: string; assuranceLevel: string; issuedAt: string; expiresAt: string; revokedAt?: string };
export type User = { id: string; email: string; passwordHash: string; birthDate?: string; country?: string; identityVerified: boolean; uniquePerson: boolean; accountValid: boolean; kycValid: boolean; investorEligible: boolean; emailVerified: boolean; roles: string[] };
export type ProofRequest = { id: string; userId: string; clientId: string; requestedClaims: string[]; status: 'PENDING'|'APPROVED'|'DENIED'; createdAt: string; decidedAt?: string; token?: string };
export type Audit = { event: string; actorId?: string; targetId?: string; at: string; metadata?: Record<string, unknown> };
export type VerifierApplication={id:string;ownerId:string;name:string;clientId:string;secretHash:string;redirectUris:string[];allowedClaims:string[];webhookUrl?:string;environment:'SANDBOX'|'PRODUCTION';status:'ACTIVE'|'SUSPENDED';createdAt:string};
export type TrustRegistryEntry={id:string;issuerName:string;issuerType:string;jurisdiction:string;assuranceLevel:string;supportedCredentials:string[];status:'TRUSTED'|'SUSPENDED'|'REVOKED';trustedSince:string;statusEndpoint?:string};

export const CLIENT_POLICIES: Record<string, Set<string>> = {
  'relationship-network': new Set(['adult_verified', 'unique_person', 'account_valid']),
  assettoken: new Set(['identity_verified', 'kyc_valid', 'jurisdiction', 'investor_eligible', 'authorized_company_signatory', 'asset_owner_verified'])
};

export async function hashPassword(password: string): Promise<string> {
  const salt = randomUUID(); const derived = await scrypt(password, salt, 64) as Buffer;
  return `${salt}:${derived.toString('hex')}`;
}
export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [salt, hex] = encoded.split(':'); if (!salt || !hex) return false;
  const derived = await scrypt(password, salt, 64) as Buffer; const expected = Buffer.from(hex, 'hex');
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}
function b64(input: string) { return Buffer.from(input).toString('base64url'); }
export class SignedCredentialProofProvider {
  constructor(private readonly secret: string, private readonly issuer: string) { if (secret.length < 32) throw new Error('proof secret must be at least 32 characters'); }
  pairwiseSubject(userId: string, clientId: string): string {
    const digest = createHmac('sha256', this.secret).update(`${clientId}\0${userId}`).digest('hex').slice(0, 20).toUpperCase();
    return `SUB-${clientId === 'relationship-network' ? 'REL' : 'ASSET'}-${digest}`;
  }
  sign(payload: Record<string, unknown>): string {
    const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: 'dev-v1' })); const body = b64(JSON.stringify(payload));
    const signature = createHmac('sha256', this.secret).update(`${header}.${body}`).digest('base64url'); return `${header}.${body}.${signature}`;
  }
  verify(token: string, audience: string): Record<string, unknown> {
    const parts = token.split('.'); if (parts.length !== 3) throw new Error('invalid proof');
    const expected = createHmac('sha256', this.secret).update(`${parts[0]}.${parts[1]}`).digest(); const actual = Buffer.from(parts[2], 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('invalid signature');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()) as Record<string, unknown>;
    if (payload.aud !== audience) throw new Error('invalid audience'); if (typeof payload.exp !== 'number' || payload.exp < Math.floor(Date.now()/1000)) throw new Error('expired proof');
    if (payload.iss !== this.issuer) throw new Error('invalid issuer'); return payload;
  }
}

export class PrivateIdService {
  users = new Map<string, User>(); credentials = new Map<string, Credential>(); requests = new Map<string, ProofRequest>(); audits: Audit[] = []; usedJti = new Set<string>(); sessions = new Map<string,{userId:string;expiresAt:number}>();
  applications=new Map<string,VerifierApplication>();trustRegistry=new Map<string,TrustRegistryEntry>();revokedAccess=new Set<string>();
  private pending:Promise<void>=Promise.resolve();
  constructor(public proofs = new SignedCredentialProofProvider(process.env.PRIVATEID_PROOF_SECRET ?? 'development-only-proof-secret-000001', process.env.PRIVATEID_ISSUER ?? 'https://privateid.local'),private store?:StateStore<any>) {}
  private snapshot(){return{users:[...this.users],credentials:[...this.credentials],requests:[...this.requests],audits:this.audits,usedJti:[...this.usedJti],sessions:[...this.sessions],applications:[...this.applications],trustRegistry:[...this.trustRegistry],revokedAccess:[...this.revokedAccess]}}
  async hydrate(){const s=await this.store?.load();if(!s)return;this.users=new Map(s.users??[]);this.credentials=new Map(s.credentials??[]);this.requests=new Map(s.requests??[]);this.audits=s.audits??[];this.usedJti=new Set(s.usedJti??[]);this.sessions=new Map(s.sessions??[]);this.applications=new Map(s.applications??[]);this.trustRegistry=new Map(s.trustRegistry??[]);this.revokedAccess=new Set(s.revokedAccess??[])}
  changed(){if(this.store){const state=this.snapshot();this.pending=this.pending.then(()=>this.store!.save(state))}return this.pending}flush(){return this.pending}
  audit(event:string, actorId?:string, targetId?:string, metadata?:Record<string,unknown>) { this.audits.push({event,actorId,targetId,metadata,at:new Date().toISOString()}); }
  async register(input: {email:string;password:string;birthDate?:string;country?:string;identityVerified?:boolean;uniquePerson?:boolean;kycValid?:boolean;investorEligible?:boolean;roles?:string[]}): Promise<User> {
    if ([...this.users.values()].some(u=>u.email===input.email.toLowerCase())) throw new Error('email already registered');
    const user: User={id:randomUUID(),email:input.email.toLowerCase(),passwordHash:await hashPassword(input.password),birthDate:input.birthDate,country:input.country,identityVerified:!!input.identityVerified,uniquePerson:!!input.uniquePerson,accountValid:true,kycValid:!!input.kycValid,investorEligible:!!input.investorEligible,emailVerified:true,roles:input.roles??['USER']}; this.users.set(user.id,user); this.audit('account.created',user.id); this.changed(); return user;
  }
  async login(email:string,password:string) { const user=[...this.users.values()].find(u=>u.email===email.toLowerCase()); if(!user||!await verifyPassword(password,user.passwordHash)||!user.accountValid) { this.audit('login.failed'); this.changed(); throw new Error('invalid credentials'); } const token=randomUUID(); this.sessions.set(token,{userId:user.id,expiresAt:Date.now()+3600000}); this.audit('login.succeeded',user.id); this.changed(); return {accessToken:token,expiresIn:3600,userId:user.id}; }
  authenticate(token?:string) { const session=token&&this.sessions.get(token); if(!session||session.expiresAt<Date.now()) throw new Error('unauthorized'); const user=this.users.get(session.userId); if(!user) throw new Error('unauthorized'); return user; }
  logout(user:User,token:string){const session=this.sessions.get(token);if(!session||session.userId!==user.id)throw new Error('not found');this.sessions.delete(token);this.audit('session.revoked',user.id);this.changed();return{revoked:true}}
  deleteAccount(user:User){user.accountValid=false;for(const[id,s]of this.sessions)if(s.userId===user.id)this.sessions.delete(id);for(const c of this.credentials.values())if(c.userId===user.id&&!c.revokedAt)c.revokedAt=new Date().toISOString();for(const r of this.requests.values())if(r.userId===user.id&&r.status==='PENDING')r.status='DENIED';this.audit('account.deletion_requested',user.id);this.changed();return{status:'DEACTIVATED',retentionNotice:'Security and consent records remain subject to documented retention policy'}}
  issueCredential(actor:User,userId:string,input:{type:string;claims:Claims;expiresInSeconds?:number;assuranceLevel?:string}) { if(!actor.roles.some(r=>['ISSUER_ADMIN','IDENTITY_ADMIN'].includes(r))) throw new Error('forbidden'); if(!this.users.has(userId)) throw new Error('user not found'); const now=Date.now(); const credential:Credential={id:randomUUID(),userId,type:input.type,claims:input.claims,issuer:'mock-trusted-identity-provider',assuranceLevel:input.assuranceLevel??'development',issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+(input.expiresInSeconds??86400)*1000).toISOString()}; this.credentials.set(credential.id,credential); this.audit('credential.issued',actor.id,credential.id,{type:credential.type}); this.changed(); return credential; }
  revokeCredential(actor:User,id:string) { if(!actor.roles.some(r=>['ISSUER_ADMIN','IDENTITY_ADMIN'].includes(r))) throw new Error('forbidden'); const credential=this.credentials.get(id); if(!credential) throw new Error('credential not found'); credential.revokedAt=new Date().toISOString(); this.audit('credential.revoked',actor.id,id); this.changed(); return credential; }
  createProofRequest(user:User,clientId:string,claims:string[]) { const registered=this.applications.get(clientId);const allowed=registered?new Set(registered.allowedClaims):CLIENT_POLICIES[clientId];if(registered?.status!=='ACTIVE'&&registered)throw new Error('client unavailable');if(this.revokedAccess.has(`${user.id}:${clientId}`))throw new Error('application access revoked'); if(!allowed||claims.length===0||claims.some(c=>!allowed.has(c))) throw new Error('claim not allowed'); const request:ProofRequest={id:randomUUID(),userId:user.id,clientId,requestedClaims:[...new Set(claims)],status:'PENDING',createdAt:new Date().toISOString()}; this.requests.set(request.id,request); this.audit('proof.requested',clientId,request.id,{claims:request.requestedClaims}); this.changed(); return request; }
  private resolveClaim(user:User,claim:string): string|boolean|number {
    const live=[...this.credentials.values()].filter(c=>c.userId===user.id&&!c.revokedAt&&new Date(c.expiresAt)>new Date()); const credentialClaim=live.find(c=>claim in c.claims)?.claims[claim]; if(credentialClaim!==undefined) return credentialClaim;
    if(claim==='adult_verified') return !!user.birthDate && new Date(user.birthDate)<=new Date(new Date().setFullYear(new Date().getFullYear()-18));
    const values:Claims={unique_person:user.uniquePerson,account_valid:user.accountValid,identity_verified:user.identityVerified,kyc_valid:user.kycValid,jurisdiction:user.country??'',investor_eligible:user.investorEligible}; return values[claim]??false;
  }
  decide(user:User,id:string,allow:boolean) { const request=this.requests.get(id); if(!request||request.userId!==user.id) throw new Error('not found'); if(request.status!=='PENDING') throw new Error('already decided'); request.status=allow?'APPROVED':'DENIED'; request.decidedAt=new Date().toISOString(); this.audit(allow?'proof.approved':'proof.denied',user.id,id,{claims:allow?request.requestedClaims:[]}); if(!allow){this.changed();return {status:request.status}} const now=Math.floor(Date.now()/1000),jti=randomUUID(); const claims=Object.fromEntries(request.requestedClaims.map(c=>[c,this.resolveClaim(user,c)])); request.token=this.proofs.sign({iss:process.env.PRIVATEID_ISSUER??'https://privateid.local',aud:request.clientId,sub:this.proofs.pairwiseSubject(user.id,request.clientId),iat:now,exp:now+300,jti,proof_request_id:id,...claims}); this.changed(); return {status:request.status,proof:request.token}; }
  verifyProof(token:string,audience:string) { const payload=this.proofs.verify(token,audience); const jti=String(payload.jti); if(this.usedJti.has(jti)) throw new Error('proof replayed'); const request=this.requests.get(String(payload.proof_request_id)); if(!request||request.status!=='APPROVED'||request.token!==token) throw new Error('proof no longer valid'); this.usedJti.add(jti); this.audit('proof.verified',audience,String(payload.proof_request_id)); this.changed(); return payload; }
  async registerApplication(actor:User,input:{name:string;clientId:string;redirectUris:string[];allowedClaims:string[];webhookUrl?:string;environment:'SANDBOX'|'PRODUCTION'}){if(!actor.roles.some(r=>['VERIFIER_ADMIN','IDENTITY_ADMIN'].includes(r)))throw new Error('forbidden');if(this.applications.has(input.clientId)||CLIENT_POLICIES[input.clientId])throw new Error('client already exists');const secret=randomUUID()+randomUUID(),application:VerifierApplication={id:randomUUID(),ownerId:actor.id,...input,secretHash:await hashPassword(secret),status:'ACTIVE',createdAt:new Date().toISOString()};this.applications.set(application.clientId,application);this.audit('verifier.registered',actor.id,application.id,{clientId:application.clientId});this.changed();return{application:{...application,secretHash:undefined},clientSecret:secret}}
  registerTrustEntry(actor:User,input:Omit<TrustRegistryEntry,'id'|'trustedSince'>){if(!actor.roles.some(r=>['IDENTITY_ADMIN','SECURITY_ADMIN'].includes(r)))throw new Error('forbidden');const entry:TrustRegistryEntry={...input,id:randomUUID(),trustedSince:new Date().toISOString()};this.trustRegistry.set(entry.id,entry);this.audit('trust_registry.created',actor.id,entry.id);this.changed();return entry}
  privacyDashboard(user:User){const approved=[...this.requests.values()].filter(r=>r.userId===user.id&&r.status==='APPROVED');return{connectedApplications:[...new Set(approved.map(r=>r.clientId))].map(clientId=>{const history=approved.filter(r=>r.clientId===clientId);const last=history.at(-1)!;return{clientId,lastProofAt:last.decidedAt,shared:[...new Set(history.flatMap(r=>r.requestedClaims))],accessRevoked:this.revokedAccess.has(`${user.id}:${clientId}`)}}),consentHistory:[...this.requests.values()].filter(r=>r.userId===user.id).map(({token,...safe})=>safe),credentialHistory:[...this.credentials.values()].filter(c=>c.userId===user.id),sessions:[...this.sessions.entries()].filter(([,s])=>s.userId===user.id).map(([id,s])=>({id,expiresAt:new Date(s.expiresAt).toISOString()}))}}
  revokeApplicationAccess(user:User,clientId:string){this.revokedAccess.add(`${user.id}:${clientId}`);for(const r of this.requests.values())if(r.userId===user.id&&r.clientId===clientId&&r.status==='PENDING')r.status='DENIED';this.audit('application.access_revoked',user.id,clientId);this.changed();return{revoked:true}}
}
