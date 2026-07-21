# Testing ZDNA RBAC via Entra (role and group)

This guide covers how to test role-based access control end to end, using two
Entra sources for role assignment:

- `role` — Entra App Roles
- `group` — Entra Security Groups

Both funnel into the same ZDNA role and its permission matrix, so the resulting
access is identical regardless of which source triggered it.

## Prerequisites (once per app)

1. An Entra App registration exists (OIDC/PKCE), with its Redirect URI set to
   the ZDNA callback (e.g. `https://emc-mdnacloud-demo-t.web.app/auth/oidc/callback`).
   For a PKCE app the redirect stays a public-client type; no client secret.
2. In ZDNA, an SSO configuration is saved and Active, with JIT Provisioning
   Enabled.
3. Note the app's Application (client) ID and Directory (tenant) ID.

Note: a role/group only takes effect on the NEXT login. Always test in a fresh
incognito window — an already-open session will not update.

---

## PART 1 — Test with "role" (Entra App Roles)

### A. Entra setup

1. Open the App registration.
2. Go to App roles. Click Create app role.
   - Display name: Zebra Admin
   - Value: Zebra.Admin
   - Allowed member types: Users/Groups
   - Check "Enable this app role".
   - Apply.
3. Repeat step 2 to create a second role with Value: Zebra.Manager
   (Display name: Zebra Manager).
4. Go to Enterprise applications, open the same app, then Users and groups.
5. Click Add user/group. Select the test user. Select a role: Zebra Admin.
   Click Assign.

### B. ZDNA setup

6. In ZDNA, open Manage roles (Role Mappings).
7. Add a mapping row:
   - Role: Admin
   - Claim Name: role
   - Claim Value: Zebra.Admin
8. Add a second mapping row:
   - Role: Manager
   - Claim Name: role
   - Claim Value: Zebra.Manager
9. Save.

### C. Test

10. Open a fresh incognito window and log in as the test user via SSO.
11. Expected result (Admin): full access. The SSO admin buttons (Edit
    Configuration, Deactivate SSO, Manage roles) are enabled. My Services,
    Roles, Users are accessible.

### D. Switch the role from Entra (proves Entra controls it)

12. In Entra, Enterprise applications, Users and groups: remove the user's
    Zebra Admin assignment, then add the user with role Zebra Manager.
13. Fresh incognito login again.
14. Expected result (Manager): limited access. The SSO admin buttons are
    disabled. My Services, Roles, Users, Device Settings, Android Updates,
    Licensing are locked.

---

## PART 2 — Test with "group" (Entra Security Groups)

### A. Entra setup

1. Go to Groups (Microsoft Entra ID > Groups). Click New group.
   - Group type: Security
   - Group name: ZDNA Managers
   - Membership type: Assigned
   - Add the test user under Members.
   - Create.
2. Open the new group, go to Overview, and copy the Object ID (a GUID).
3. Add the groups claim to the token:
   - Open the App registration.
   - Go to Token configuration. Click Add groups claim.
   - Select Security groups. Add.
   Without this step the token has no group data and the mapping will never
   match.

### B. Entra assignment cleanup (so only the group drives the role)

4. In Enterprise applications, Users and groups: make sure the user does NOT
   hold the Zebra Admin or Zebra Manager app role.
   - Set the user's assignment to Default Access, OR remove the app-role
     assignment.
   - Default Access emits no role, so only the group will decide the role.
   - Note: only fully remove the assignment if Properties > "Assignment
     required?" is No; otherwise the user cannot log in.

### C. ZDNA setup

5. In ZDNA, open Manage roles.
6. Add a mapping row:
   - Role: Manager
   - Claim Name: group
   - Claim Value: (paste the group Object ID from step 2)
7. Save.

### D. Test

8. Open a fresh incognito window and log in as the test user.
9. Expected result: the user resolves to Manager (limited access) based on
   group membership, even though no app role is assigned.

### E. Switch the role from Entra

10. To grant: add the user to the group. To revoke: remove the user from the
    group.
11. Fresh incognito login to see the change.

---

## PART 3 — Other mapping sources

Besides `role` and `group`, the same Manage roles screen supports four more
Claim Name values. They work the same way: add a mapping row with the Claim
Name and Claim Value below, save, then test with a fresh incognito login.

Combining rule: all matching mappings accumulate (a user matched by two sources
gets both roles), except `default`, which applies only when nothing else
matched.

### 3.1 department

Assign a role based on the user's department.

1. Entra: make sure the test user's Department field is set (user profile).
2. ZDNA mapping row:
   - Role: (the role you want, e.g. Manager)
   - Claim Name: department
   - Claim Value: the department to match (e.g. IT)
3. Fresh incognito login. Users whose department equals the value get the role.

Notes:
- The id_token does not carry department. ZDNA fetches it from Microsoft Graph
  at login, which happens only when JIT is enabled and requires the app's Graph
  User.Read (profile) permission.
- If the Graph fetch fails, this mapping simply does not match that login; the
  login still succeeds.

### 3.2 jobtitle

Assign a role based on the user's job title.

1. Entra: make sure the test user's Job title field is set (user profile).
2. ZDNA mapping row:
   - Role: (the role you want)
   - Claim Name: jobtitle
   - Claim Value: the title to match (e.g. Manager)
3. Fresh incognito login.

Notes:
- Same as department: sourced from Microsoft Graph, requires JIT enabled and
  Graph profile permission.

### 3.3 default

A catch-all role for any user who matched no other mapping. Use this as a
least-privilege fallback so a no-match user is not left with default-allow
access.

1. ZDNA mapping row:
   - Role: a minimal role (e.g. Viewer)
   - Claim Name: default
   - Claim Value: leave empty
2. Fresh incognito login as a user who matches no other mapping.

Notes:
- The default mapping applies only when no other mapping matched. If any other
  source matches, default is ignored.

### 3.4 Any custom Entra claim

Assign a role based on any claim you emit in the token (for example
employeeType, employeeId, or a directory extension attribute).

1. Entra: make sure the claim is actually emitted in the token.
   - App registration > Token configuration > Add optional claim (or a
     directory extension attribute).
2. ZDNA mapping row:
   - Role: (the role you want)
   - Claim Name: the exact claim key (e.g. employeeType)
   - Claim Value: the value to match (e.g. Contractor)
3. Fresh incognito login.

Notes:
- The claim name is matched case-insensitively, but the claim must be present in
  the token. If it is missing (typo or not emitted), nothing matches and a
  jit_unknown_claim warning is logged.

---

## What to verify after each login

1. The correct role label is applied (Admin unlocks the SSO admin buttons;
   Manager does not).
2. Locked areas match the role's permission matrix (Manager has several areas
   locked; Admin does not).
3. Changes only appear after a fresh login, not on refresh.

## Troubleshooting (if the user gets no role or the wrong role)

1. App role State must be Enabled (a disabled role is never sent in the token).
2. For "role": the user must be assigned that app role in Enterprise
   applications > Users and groups.
3. For "group": the groups claim must be added in Token configuration, and the
   Claim Value must be the group Object ID (GUID), not the group name.
4. Claim Value must match exactly (Zebra.Admin, Zebra.Manager, or the exact
   GUID).
5. For admin-specific UI, the ZDNA mapping Role name must be exactly Admin.
6. If the user has both an app role and a group that map to different roles,
   they accumulate; remove one source to get a single clean role.
7. Always retest with a fresh incognito login.

---

## How it works (reference)

- Claim Name = which token claim to read: `role` = Entra App Roles claim,
  `group` = Entra security groups claim. Other supported sources: `department`,
  `jobtitle`, `default`, or any raw claim name.
- Claim Value = the value to match in that claim (app-role Value, or group
  Object ID).
- ZDNA maps the matched claim to a role name, then derives that role's
  permissions (from RMS, or the role's Firestore role config) to enforce access
  as a deny-list.
- Two kinds of "admin access": feature/page access comes from the role's
  permission matrix; the SSO-admin buttons are gated on the role name being
  exactly "Admin".
