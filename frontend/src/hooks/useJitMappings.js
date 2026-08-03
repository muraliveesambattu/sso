import { useState, useMemo, useCallback } from 'react';

const EMPTY_ROW = {
  zdna_role: '',
  mapping_source: '',
  mapping_value: '',
};

const validateMappings = (rows) => {
  const errors = {};
  const roleClaimMap = new Map();
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
    claimNames.forEach((claimName) => {
      const roleClaimKey = `${role}__${claimName}`;
      if (roleClaimMap.has(roleClaimKey)) {
        const prevIndex = roleClaimMap.get(roleClaimKey);
        errors[index] = 'Same role must have different Claim Name';
        errors[prevIndex] = 'Same role must have different Claim Name';
      } else {
        roleClaimMap.set(roleClaimKey, index);
      }
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
  });
  return errors;
};

export const useJitMappings = (initial = [EMPTY_ROW]) => {
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

  const mappingErrors = useMemo(() => validateMappings(jitMappings), [jitMappings]);

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
