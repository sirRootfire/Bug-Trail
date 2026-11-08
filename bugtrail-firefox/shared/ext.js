export const api = globalThis.browser ?? globalThis.chrome;
export const send = (type, payload = {}) => api.runtime.sendMessage({ type, ...payload });
