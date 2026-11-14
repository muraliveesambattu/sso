import { useState, useMemo, useCallback } from 'react';
import {
  MAX_CLAIM_NAME_LENGTH,
  ROLE_CLAIMS,
  GROUP_CLAIMS,
  USER_ATTRIBUTE_CLAIMS,
  ENTRA_CLAIM_ERRORS,
} from '../constants/SsoConstants';

const EMPTY_ROW = {
  zdna_role: '',
  mapping_source: '',
  mapping_value: '',
};

const norm = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');

// Same rules as the backend (entraClaimsCatalog.service checkMappingAgainstCatalog)
// and as login matching, so a row that passes here is saved and can match at login.
// entraClaims: { claimNames, roles, groups: [{ id, name }],
//   userAttributes: { departments, jobTitles } | null } from useEntraClaims.
// userAttributes is null when Entra users can't be read; department and job
// title are then not checked.
export const checkAgainstEntra = (row, entraClaims) => {
  const name = norm(row.mapping_source);
  const value = (row.mapping_value || '').trim();
  if (name === 'default') return null;
  if (name.length > MAX_CLAIM_NAME_LENGTH) {
    return ENTRA_CLAIM_ERRORS.claimNameTooLong(MAX_CLAIM_NAME_LENGTH);
  }
  if (!entraClaims.claimNames.some((n) => norm(n) === name)) {
    return ENTRA_CLAIM_ERRORS.claimNotConfigured(row.mapping_source.trim());
  }
  if (ROLE_CLAIMS.has(name) && !entraClaims.roles.some((r) => norm(r) === norm(value))) {
    return ENTRA_CLAIM_ERRORS.roleNotFound(value);
  }
  if (GROUP_CLAIMS.has(name)
    && !entraClaims.groups.some((g) => g.id === value || (g.name && norm(g.name) === norm(value)))) {
    return ENTRA_CLAIM_ERRORS.groupNotFound(value);
  }
  const attribute = USER_ATTRIBUTE_CLAIMS[name];
  if (attribute && entraClaims.userAttributes) {
    const known = entraClaims.userAttributes[attribute.key] || [];
    if (!known.some((v) => norm(v) === norm(value))) {
      return ENTRA_CLAIM_ERRORS.attributeNotFound(attribute.label, value);
    }
  }
  return null;
};

const validateMappings = (rows, entraClaims) => {
  const errors = {};
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
      errors[index] = 'All fields are required';
    }
    // Only check against Entra once the row is complete; undefined catalog → no check.
    if (!errors[index]) {
      const entraProblem = entraClaims ? checkAgainstEntra(row, entraClaims) : null;
      if (entraProblem) errors[index] = entraProblem;
    }
  });
  return errors;
};

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

  const mappingErrors = useMemo(() => validateMappings(jitMappings, entraClaims), [jitMappings, entraClaims]);

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
