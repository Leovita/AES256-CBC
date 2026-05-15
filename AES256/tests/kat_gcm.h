#pragma once

// Esegue i KAT AES-256-GCM con vettori NIST SP 800-38D Appendix B (TC13-TC16).
// Restituisce il numero di test falliti (0 = tutti OK).
int runKatTests();
