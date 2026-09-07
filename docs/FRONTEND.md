# Frontend

React/Vite serves `/site/`. Customer entry, recovery and security are in `account.tsx`; wallet, proof consent, connections and billing are in `wallet.tsx`; issuer/verifier/organization workflows are in `workspaces.tsx`; staff operations are in `admin.tsx`. `api.ts` centralizes cookie/CSRF handling, typed public DTOs and abortable fetches. `components.tsx` provides labeled fields, asynchronous forms, paginated records and safe feedback.

Each page/resource owns its data and clears it when its path changes. Navigation remounts page state, aborts obsolete fetches and prevents late responses from updating unmounted pages. Sessions cannot become billing data. Forms disable duplicate submission, retain understandable validation errors, focus errors, and report success with live regions. Expired sessions return customers to entry. No bearer or client secret is stored in localStorage. One-time secrets appear only in the current component and must be saved explicitly.

Consent shows the reviewed recipient/purpose, exact claim values and expiry before approval. The approval binds the preview hash, so changed conclusions require another review. Federation values are validated by the API, and only its approved redirect result is followed. Verification/reset fragments are consumed into memory and removed from history, including when a link is opened in the current tab.

Keyboard navigation, a skip link, labeled fields, focus indicators, loading/error live regions, reduced-motion support and a 390-pixel layout are implemented. Browser regressions cover these entry behaviors and main journeys. Assistive-technology review across additional browsers and languages is still a release responsibility; the project does not claim WCAG certification.

Vite proxies `/api`, `/openapi.json` and `/.well-known` to port 3001. `npm run typecheck` checks frontend types separately; `npm run build:web` bundles without substituting for typechecking. Production CSP permits only local scripts/styles/connections and rejects frames/object embedding. No third-party analytics or remote fonts are loaded.
