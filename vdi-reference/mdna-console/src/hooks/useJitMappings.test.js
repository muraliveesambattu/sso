/**
 * useJitMappings — JIT row state + validation rules.
 *
 * Stack: React 16 + @testing-library/react-hooks v8 (RTL v12 has no renderHook).
 * No antd or DOM needed — this hook is pure state.
 */

import { renderHook, act } from '@testing-library/react-hooks';
import { useJitMappings } from './useJitMappings';

const row = (zdna_role, mapping_source, mapping_value, id) => ({
  zdna_role, mapping_source, mapping_value, ...(id ? { id } : {}),
});

describe('useJitMappings — initial state', () => {
  test('starts with one empty row when no initial value is given', () => {
    const { result } = renderHook(() => useJitMappings());
    expect(result.current.jitMappings).toHaveLength(1);
    expect(result.current.jitMappings[0]).toMatchObject({
      zdna_role: '', mapping_source: '', mapping_value: '',
    });
  });

  test('seeds from the supplied rows', () => {
    const initial = [row('Admin', 'group', 'zdna-admins', 'r1')];
    const { result } = renderHook(() => useJitMappings(initial));
    expect(result.current.jitMappings).toEqual(initial);
  });
});

describe('useJitMappings — row operations', () => {
  test('updateMapping changes only the targeted field of the targeted row', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Viewer', 'group', 'b', 'r2')])
    );

    act(() => result.current.updateMapping(1, 'mapping_value', 'c'));

    expect(result.current.jitMappings[0]).toMatchObject({ mapping_value: 'a' });
    expect(result.current.jitMappings[1]).toMatchObject({ zdna_role: 'Viewer', mapping_value: 'c' });
  });

  test('addMapping appends a blank row', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', 'group', 'a', 'r1')]));
    act(() => result.current.addMapping());
    expect(result.current.jitMappings).toHaveLength(2);
    expect(result.current.jitMappings[1]).toMatchObject({ zdna_role: '' });
  });

  test('removeMapping drops the row at the index', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Viewer', 'group', 'b', 'r2')])
    );
    act(() => result.current.removeMapping(0));
    expect(result.current.jitMappings).toEqual([row('Viewer', 'group', 'b', 'r2')]);
  });

  test('resetMappings replaces all rows, and falls back to one empty row', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', 'group', 'a', 'r1')]));

    act(() => result.current.resetMappings([row('Viewer', 'dept', 'IT', 'r9')]));
    expect(result.current.jitMappings).toEqual([row('Viewer', 'dept', 'IT', 'r9')]);

    act(() => result.current.resetMappings());
    expect(result.current.jitMappings).toEqual([{ zdna_role: '', mapping_source: '', mapping_value: '' }]);
  });

  // KNOWN ISSUE — documents current behaviour, not desired behaviour.
  // EMPTY_ROW carries no `id`, and addMapping spreads it verbatim, so every
  // added row renders with key={undefined} in JitMappingSection. Two or more
  // added rows collide on the same React key. Fix: `{ ...EMPTY_ROW, id: crypto.randomUUID() }`.
  test('added rows currently have no id (React key collision in JitMappingSection)', () => {
    const { result } = renderHook(() => useJitMappings([]));
    act(() => result.current.addMapping());
    act(() => result.current.addMapping());
    expect(result.current.jitMappings[0].id).toBeUndefined();
    expect(result.current.jitMappings[1].id).toBeUndefined();
  });
});

describe('useJitMappings — validation', () => {
  test('a fully empty row is exempt (empty-string marker, not an error message)', () => {
    const { result } = renderHook(() => useJitMappings([row('', '', '')]));
    expect(result.current.mappingErrors[0]).toBe('');
    expect(result.current.isJitValid(true)).toBe(false); // key present ⇒ not valid
  });

  test('a partially filled row is flagged as incomplete', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', '', '')]));
    expect(result.current.mappingErrors[0]).toMatch(/All fields .* are required/);
  });

  test('a complete row produces no errors', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', 'group', 'zdna-admins', 'r1')]));
    expect(result.current.mappingErrors).toEqual({});
    expect(result.current.isJitValid(true)).toBe(true);
  });

  test('same role twice on the same claim name is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Admin', 'group', 'b', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('same role on different claim names is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Admin', 'department', 'IT', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('different roles sharing a claim name AND value is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'same', 'r1'), row('Viewer', 'group', 'same', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('different roles sharing a claim name but different values is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Viewer', 'group', 'b', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('same role repeating a claim name across rows is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'GROUP, dept', 'x', 'r1'), row('Admin', 'group', 'y', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('same value in different case across roles is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', '  Same  ', 'r1'), row('Viewer', 'group', 'same', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('isJitValid(false) short-circuits to true regardless of errors', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', '', '')]));
    expect(result.current.mappingErrors[0]).toBeTruthy();
    expect(result.current.isJitValid(false)).toBe(true);
  });

  test('validation re-runs when a row is edited', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', 'group', '', 'r1')]));
    expect(result.current.mappingErrors[0]).toBeTruthy();

    act(() => result.current.updateMapping(0, 'mapping_value', 'zdna-admins'));
    expect(result.current.mappingErrors).toEqual({});
  });
});

describe('useJitMappings — checked against the Entra app (live)', () => {
  const GROUP_ID = 'aaaaaaaa-1111-2222-3333-444444444444';
  const entraClaims = {
    claimNames: ['role', 'roles', 'group', 'groups', 'department', 'jobtitle', 'employeeType'],
    roles: ['Zebra.Admin', 'Zebra.Viewer'],
    groups: [{ id: GROUP_ID, name: 'ZDNA Admins' }],
  };
  const render = (rows, claims = entraClaims) =>
    renderHook(() => useJitMappings(rows, { entraClaims: claims }));

  test('accepts claim names and values that exist in the Entra app', () => {
    const { result } = render([
      row('Admin', 'Role', ' zebra.admin ', 'r1'),
      row('Viewer', 'groups', GROUP_ID, 'r2'),
      row('Viewer', 'group', 'zdna admins', 'r3'),
      row('Viewer', 'department', 'Any department', 'r4'),
      row('Viewer', 'employeetype', 'Contractor', 'r5'),
    ]);
    expect(result.current.mappingErrors).toEqual({});
    expect(result.current.isJitValid(true)).toBe(true);
  });

  test('flags a claim name the Entra app does not send', () => {
    const { result } = render([row('Admin', 'rol', 'Zebra.Admin', 'r1')]);
    expect(result.current.mappingErrors[0]).toMatch(/Claim "rol" is not configured for this app/);
    expect(result.current.isJitValid(true)).toBe(false);
  });

  test('flags several claim names typed into one row', () => {
    const { result } = render([row('Admin', 'GROUP, dept', 'x', 'r1')]);
    expect(result.current.mappingErrors[0]).toMatch(/is not configured for this app/);
  });

  test('flags a role value that is not an app role', () => {
    const { result } = render([row('Admin', 'role', 'Zebra.Owner', 'r1')]);
    expect(result.current.mappingErrors[0]).toMatch(/"Zebra.Owner" is not an app role/);
  });

  test('flags a group that is not assigned to the app (ids match exactly)', () => {
    const { result } = render([row('Admin', 'group', GROUP_ID.toUpperCase(), 'r1')]);
    expect(result.current.mappingErrors[0]).toMatch(/is not a group assigned to this app/);
  });

  test('flags a claim name longer than 30 characters', () => {
    const { result } = render([row('Admin', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role', 'Zebra.Admin', 'r1')]);
    expect(result.current.mappingErrors[0]).toMatch(/30 characters or fewer/);
  });

  test('re-checks as the admin types', () => {
    const { result } = render([row('Admin', 'role', 'Zebra.Own', 'r1')]);
    expect(result.current.isJitValid(true)).toBe(false);
    act(() => result.current.updateMapping(0, 'mapping_value', 'Zebra.Viewer'));
    expect(result.current.mappingErrors).toEqual({});
    expect(result.current.isJitValid(true)).toBe(true);
  });

  test('skips the Entra check when no catalog is given', () => {
    const { result } = renderHook(() => useJitMappings([row('Admin', 'anything', 'x', 'r1')]));
    expect(result.current.mappingErrors).toEqual({});
    expect(result.current.isJitValid(true)).toBe(true);
  });
});
