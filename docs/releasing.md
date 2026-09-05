# Release and maintenance

`@0-auth/zero-auth` publishes from GitHub Releases. A published GitHub release
triggers its npm workflow; do not run a second manual npm publish for the same
version. The IdP packages use the explicit package selector described below.

## IdP and MongoDB adapter releases

> [!WARNING]
> Do not create a GitHub Release to publish an IdP package: the current release
> event always selects `@0-auth/zero-auth`. Use the `Publish to npm` workflow's
> package selector instead. Existing package versions must remain unchanged.

For `@0-auth/zero-auth-idp-mongodb@0.1.0`:

1. Date the adapter changelog and keep any migration warning at the start of its
   README. Confirm the version in its manifest, build banner, and lockfile agree.
2. Build the IdP dependency, then run the adapter's release checks:

   ```bash
   npm run build --workspace @0-auth/zero-auth-idp
   npm run prepublishOnly --workspace @0-auth/zero-auth-idp-mongodb
   npm run test:coverage --workspace @0-auth/zero-auth-idp-mongodb
   npm run test:integration --workspace @0-auth/zero-auth-idp-mongodb
   npm pack --workspace @0-auth/zero-auth-idp-mongodb
   ```

   Set `MONGODB_URI` for the integration tests; without it, they are skipped.
   Install the resulting tarball outside the monorepo with the published IdP
   peer and MongoDB driver 6. Check CommonJS, ESM, TypeScript declarations, and
   real storage operations. Do not substitute workspace links for this check.

3. Commit and push the release preparation, then wait for CI to pass. Obtain
   publishing approval before dispatching:

   ```bash
   gh workflow run publish.yml --ref master -f package=zero-auth-idp-mongodb
   ```

4. Wait for that workflow to succeed, verify
   `npm view @0-auth/zero-auth-idp-mongodb@0.1.0 version dist.tarball`, and repeat
   the clean consumer check using the registry version. Do not also publish from
   the local terminal.
5. Only after publication, remove repository "not published yet" notes and switch
   the Express IdP example's `file:` dependencies to npm versions. Regenerate its
   lockfile and rerun its end-to-end test before committing those changes.

The same dispatch path applies to `@0-auth/zero-auth-idp` with
`-f package=zero-auth-idp`. The remaining sections describe the original
`@0-auth/zero-auth` release process.

## Before a release

1. Confirm the working tree is clean except for the intended changes.
2. Update the package version in `packages/zero-auth/package.json` and
   `package-lock.json`.
3. Add the release entry to `packages/zero-auth/CHANGELOG.md`.
4. Put breaking changes and upgrade steps at the start of
   `packages/zero-auth/README.md`.
5. Update examples and API-facing documentation.
6. Run the complete local gate:

```bash
npm run format:check
npm run lint
npm run typecheck
npm run test:coverage
npm run build
npm run docs:build
npm pack --workspace @0-auth/zero-auth --dry-run
```

Run both examples when their dependencies are available:

```bash
cd examples/express-rest-api
npm test

cd ../express-cookies-redis
npm test
```

## Commit and push

Use a focused conventional commit and push the branch used by CI:

```bash
git status
git add .
git commit -m "release: vX.Y.Z"
git push origin master
```

Wait for the normal CI workflow to pass before creating the release.

## Create the GitHub release

Create a tag that points at the verified commit:

```bash
gh release create vX.Y.Z \
  --target master \
  --title "vX.Y.Z" \
  --notes-file release-notes.md
```

The release notes should summarize user-visible changes, migrations, security
implications, and links to the changelog. Use the version without a leading
v in package.json and the leading v for the Git tag.

## Verify publication

Check all three sources:

```bash
gh run list --workflow publish.yml --limit 1
npm view @0-auth/zero-auth version
npm view @0-auth/zero-auth@X.Y.Z dist.tarball
```

Then test a clean consumer installation:

```bash
mkdir /tmp/zero-auth-release-check
cd /tmp/zero-auth-release-check
npm init -y
npm install @0-auth/zero-auth@X.Y.Z express
```

Import both module formats and exercise token generation, verification, and
the public middleware API.

## Documentation publishing

The package documentation source lives in `packages/zero-auth/README.md` and
`packages/zero-auth/CHANGELOG.md`. Repository and site documentation lives in
`docs/`. Generated TypeDoc output lives in `docs/api/` and is intentionally
ignored. It is rebuilt by `npm run docs:build` and should not be edited by hand.

The npm tarball includes the package README, changelog, license, compiled
builds, and TypeScript declarations. The full VitePress site is maintained
from the repository `docs/` directory.

## Rollback

If the release is faulty:

1. Stop promoting the release in application deployments.
2. Publish a corrective patch version; do not overwrite an npm version.
3. Document the issue and migration in the next changelog entry.
4. If secrets or refresh state are affected, rotate them or revoke the
   affected token families.

Never reuse a released version number.
