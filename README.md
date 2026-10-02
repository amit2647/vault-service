# vault-service

Vault service for OmniCore's profession-bundle platform — encrypted portal credentials (reveal is audited) and client files kept in the S3 store.

Port 4012; reached through Kong at `/api/vault`. Profession-neutral: what it
stores and how it behaves comes from the organization's installed bundle (see `bundle-sdk`).

Follows the shared service layout: `src/app.js`, `routes/`, `controllers/`, `services/`
(SQL lives there), and the copied `middleware/` (JWT + live access grants,
`requirePermission`). Schema is owned by the `migrations` repo, never by this service.

```bash
npm test && npm run lint
```
