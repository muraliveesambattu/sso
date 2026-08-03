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

  test('same role twice on the same claim name is rejected — both rows flagged', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Admin', 'group', 'b', 'r2')])
    );
    expect(result.current.mappingErrors[0]).toBe('Same role must have different Claim Name');
    expect(result.current.mappingErrors[1]).toBe('Same role must have different Claim Name');
  });

  test('same role on different claim names is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Admin', 'department', 'IT', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('different roles sharing a claim name AND value is rejected — ambiguous mapping', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'same', 'r1'), row('Viewer', 'group', 'same', 'r2')])
    );
    expect(result.current.mappingErrors[0]).toMatch(/different Claim Value/);
    expect(result.current.mappingErrors[1]).toMatch(/different Claim Value/);
  });

  test('different roles sharing a claim name but different values is allowed', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', 'a', 'r1'), row('Viewer', 'group', 'b', 'r2')])
    );
    expect(result.current.mappingErrors).toEqual({});
  });

  test('claim names are comma-split and matched case-insensitively', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'GROUP, dept', 'x', 'r1'), row('Admin', 'group', 'y', 'r2')])
    );
    // 'GROUP' from row 0 collides with 'group' from row 1 for the same role
    expect(result.current.mappingErrors[0]).toBe('Same role must have different Claim Name');
    expect(result.current.mappingErrors[1]).toBe('Same role must have different Claim Name');
  });

  test('values are trimmed and compared case-insensitively', () => {
    const { result } = renderHook(() =>
      useJitMappings([row('Admin', 'group', '  Same  ', 'r1'), row('Viewer', 'group', 'same', 'r2')])
    );
    expect(result.current.mappingErrors[0]).toMatch(/different Claim Value/);
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
