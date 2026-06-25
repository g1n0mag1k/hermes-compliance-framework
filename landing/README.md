# hermesrelay.dev landing

Marketing landing page for [hermesrelay.dev](https://hermesrelay.dev).

## Stack

- Next.js 15 (App Router)
- TypeScript
- Tailwind CSS v4 (no UI libraries)
- CSS-only animations (no animation library)

## Project layout

```
app/
  layout.tsx
  page.tsx
components/
  Hero.tsx
  Problem.tsx
  Solution.tsx
  Architecture.tsx
  Differentiators.tsx
  SocialProof.tsx
  CTA.tsx
  Footer.tsx
lib/
  constants.ts
```

## Develop

```bash
npm install
npm run dev
```

Open <http://localhost:3000>.

## Scripts

- `npm run dev` — start the dev server
- `npm run build` — production build
- `npm run start` — run the production server
- `npm run lint` — run ESLint
