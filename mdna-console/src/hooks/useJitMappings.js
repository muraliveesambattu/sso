import { useState, useMemo, useCallback } from 'react';

const EMPTY_ROW = {
  zdna_role: '',
  mapping_source: '',
  mapping_value: '',
};

const MAX_CLAIM_NAME_LENGTH = 30; // jit_mappings.mapping_source is VARCHAR(30)
const ROLE_CLAIMS = new Set(['role', 'roles']);
const GROUP_CLAIMS = new Set(['group', 'groups']);

const norm = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');

// Same rules as the backend (entraClaimsCatalog.service checkMappingAgainstCatalog)
// and as login matching, so a row that passes here is saved and can match at login.
// entraClaims: { claimNames, roles, groups: [{ id, name }] } from useEntraClaims.
export const checkAgainstEntra = (row, entraClaims) => {
  const name = norm(row.mapping_source);
  const value = (row.mapping_value || '').trim();
  if (name === 'default') return null;
  if (name.length > MAX_CLAIM_NAME_LENGTH) {
    return `Claim name must be ${MAX_CLAIM_NAME_LENGTH} characters or fewer`;
  }
  if (!entraClaims.claimNames.some((n) => norm(n) === name)) {
    return `Claim "${row.mapping_source.trim()}" is not configured for this app in Microsoft Entra`;
  }
  if (ROLE_CLAIMS.has(name) && !entraClaims.roles.some((r) => norm(r) === norm(value))) {
    return `"${value}" is not an app role of this app in Microsoft Entra`;
  }
  if (GROUP_CLAIMS.has(name)
    && !entraClaims.groups.some((g) => g.id === value || (g.name && norm(g.name) === norm(value)))) {
    return `"${value}" is not a group assigned to this app in Microsoft Entra`;
  }
  return null;
};

const validateMappings = (rows, entraClaims) => {
  const errors = {};
  const claimValueMap = new Map();
  rows.forEach((row, index) => {
    const role = row.zdna_role?.trim();
    const claimNames = row.mapping_source
      ?.split(',')
      .map((v) => v.trim().toLowerCase())
      .filter(Boolean);
    const claimValue = row.mapping_value?.trim().toLowerCase();
    const isCompletelyEmpty = !role && !claimNames?.length && !claimValue;
    if (isCompletelyEmpty) {
      errors[index] = '';
      return;
    }
    if (!role || !claimNames?.length || !claimValue) {
      errors[index] = 'All fields (Role, Claim Name, Claim Value) are required';
      return;
    }
    // The same role may repeat a claim name (e.g. Manager on role=A and role=B);
    // only different roles on the same claim name AND value are ambiguous.
    claimNames.forEach((claimName) => {
      const claimValueKey = `${claimName}__${claimValue}`;
      if (claimValueMap.has(claimValueKey)) {
        const prev = claimValueMap.get(claimValueKey);
        if (prev.role !== role) {
          errors[index] = 'Different roles with same Claim Name must have different Claim Value';
          errors[prev.index] = 'Different roles with same Claim Name must have different Claim Value';
        }
      } else {
        claimValueMap.set(claimValueKey, { role, index });
      }
    });
    if (!errors[index]) {
      const entraProblem = entraClaims ? checkAgainstEntra(row, entraClaims) : null;
      if (entraProblem) errors[index] = entraProblem;
    }
  });
  return errors;
};

/**
 * @param initial      starting rows
 * @param entraClaims  catalog from useEntraClaims; when present, rows are checked
 *                     against it as the admin types. Undefined → no Entra check.
 */
export const useJitMappings = (initial = [EMPTY_ROW], { entraClaims } = {}) => {
  const [jitMappings, setJitMappings] = useState(initial);

  const updateMapping = useCallback((idx, field, value) => {
    setJitMappings((prev) =>
      prev.map((row, i) => (i === idx ? { ...row, [field]: value } : row))
    );
  }, []);

  const addMapping = useCallback(() => {
    setJitMappings((prev) => [...prev, { ...EMPTY_ROW }]);
  }, []);

  const removeMapping = useCallback((idx) => {
    setJitMappings((prev) => prev.filter((_, i) => i !== idx));
  }, []);

  const resetMappings = useCallback((rows = [EMPTY_ROW]) => {
    setJitMappings(rows);
  }, []);

  const mappingErrors = useMemo(
    () => validateMappings(jitMappings, entraClaims),
    [jitMappings, entraClaims]
  );

  const isJitValid = useCallback((jitEnabled) => {
    if (!jitEnabled) {
      if (jitMappings.length === 0) {
        addMapping();
      }
      return true;
    }
    return Object.keys(mappingErrors).length === 0;
  }, [mappingErrors, addMapping, jitMappings.length]);

  return {
    jitMappings,
    updateMapping,
    addMapping,
    removeMapping,
    resetMappings,
    isJitValid,
    mappingErrors,
  };
};
