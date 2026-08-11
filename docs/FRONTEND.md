# Web application

The Vite/React source is in `web/`; `npm run build:web` emits `web-dist/`, which the Fastify production server mounts at `/site/`. The layout follows the cobalt identity-workspace reference in `design/dashboard-concept.png`. Browser-verified desktop and narrow renders are stored as `design/dashboard-render.png` and `design/mobile-render.png`.

Plan metadata is loaded from `/billing/plans`. Checkout, customer details, and administrator data require the bearer session stored by the client as `privateid_token`. The administrator panel calls `/admin/overview` and `/admin/customers`; the API remains the role-enforcement boundary. At narrow widths navigation becomes a three-column touch grid, content panels stack, and tables become horizontally scrollable.
