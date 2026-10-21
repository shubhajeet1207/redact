declare module 'virtual:spymonk-wasm' {
  /** The engine's WebAssembly bytes, base64-encoded at build time. */
  const base64: string;
  export default base64;
}

/** Build identity injected by vite.config.ts. */
declare const __BUILD_INFO__: {
  TOOL_VERSION: string;
  RULES_VERSION: string;
  RULES_SHA256: string;
  RULES_SHA256_SHORT: string;
  COMMIT: string;
};
