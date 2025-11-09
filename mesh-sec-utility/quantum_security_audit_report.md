# 🚀 MESHSEC QUANTUM SUPREME SECURITY AUDIT REPORT
## 📊 Executive Summary
### 🔍 Scan Overview
- **Tool**: MeshSec Quantum Sentinel 20.1 QUANTUM SENTINEL SUPREME MAX PRO PLUS ULTRA MEGA
- **Database Version**: 2024.2
- **Scan Date**: Tue Oct 14 23:03:11 2025
- **Duration**: 15 seconds
- **Files Scanned**: 37
- **Lines Analyzed**: 27864
- **Scan Speed**: 1860 lines/second
- **Security Rules**: 2000+

### 🎯 Security Metrics
- **Total Issues**: 6590
- **Critical Issues**: 3060
- **High Severity**: 3530
- **Medium Severity**: 0
- **Low Severity**: 0
- **Informational**: 0

### 📈 Risk Assessment
- **Overall Risk Score**: 10.00/10.0
- **Files At Risk**: 37
- **Security Rating**: 🔴 CRITICAL

## 🚨 Detailed Security Issues
### 💀 Critical Issues (3060)
#### 1. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 2. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 3. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 4. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 5. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 6. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 7. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 8. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 9. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 10. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:42:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 11. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 12. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 13. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 14. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 15. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 16. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 17. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 18. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 19. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 20. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:55:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 21. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 22. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 23. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 24. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 25. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 26. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 27. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 28. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 29. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 30. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:68:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 31. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 32. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 33. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 34. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 35. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 36. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 37. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 38. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 39. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 40. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:81:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 41. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 42. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 43. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 44. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 45. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 46. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 47. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 48. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 49. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
#### 50. 💀 ПЕРЕПОЛНЕНИЕ БУФЕРА: strcpy — смертельно опасен
- **File**: `/home/just/mesh_proto/mesh-protocol/src/meshratchet.c:94:9`
- **Category**: MEMORY_SAFETY
- **CWE**: [CWE-120](https://cwe.mitre.org/data/definitions/120.html)
- **CVSS**: 8.0/10.0
- **Language**: C
- **Fix**: Используйте strncpy() с указанием размера
```C
        strcpy(sha256_hash, "ERROR");
```
**Fixed Version:**
```C
strncpy(dest, src, sizeof(dest) - 1); dest[sizeof(dest)-1] = '\0';
```
### 🔥 High Severity Issues (3530)
#### 1. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 2. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 3. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 4. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 5. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 6. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 7. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 8. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 9. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 10. 💀 УЯЗВИМОСТЬ ФОРМАТНОЙ СТРОКИ: user-controlled format
- **File**: `/home/just/mesh_proto/mesh-protocol/meshratchet.c:86`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-134
- **Fix**: Используйте printf("%s", input)
**Fixed Version:**
```C
printf("%s", user_input);
```
#### 11. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 12. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 13. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 14. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 15. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 16. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 17. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 18. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 19. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 20. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/serialization.c:42`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 21. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 22. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 23. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 24. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 25. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 26. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 27. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 28. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 29. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```
#### 30. 📏 НЕПРАВИЛЬНЫЙ РАЗМЕР: memcpy с sizeof(pointer) вместо sizeof(structure)
- **File**: `/home/just/mesh_proto/mesh-protocol/session/storage.c:50`
- **Category**: MEMORY_SAFETY
- **CWE**: CWE-131
- **Fix**: Используйте sizeof(*pointer) или sizeof(structure)
**Fixed Version:**
```C
memcpy(dst, src, sizeof(*src));
```

## 📊 Statistical Analysis
### 🗂️ Issue Distribution by Category
- **Cryptography**: 280 issues
- **Memory Safety**: 6140 issues
- **Injection**: 170 issues
- **Configuration**: 0 issues

### ⚡ Performance Metrics
- **Total Scan Time**: 15 seconds
- **Average Speed**: 1860 lines/second
- **Files Processed**: 37
- **Files Skipped**: 0
- **Files Failed**: 0

## 🛠️ Remediation Guide
### 🎯 Priority Actions
1. **IMMEDIATE (0-24 hours)**: Fix 3060 CRITICAL issues
2. **URGENT (1-3 days)**: Fix 3530 HIGH severity issues

### 🔧 Security Recommendations
- Implement secure coding standards
- Conduct regular security training
- Establish code review processes
- Implement automated security testing
- Use dependency vulnerability scanning
- Conduct penetration testing

---
*Generated by MeshSec Quantum Sentinel 20.1 QUANTUM SENTINEL SUPREME MAX PRO PLUS ULTRA MEGA*
*Database Version: 2024.2*
*AI-Powered Security Analysis | Quantum-Resistant Cryptography | Zero-Trust Architecture*
