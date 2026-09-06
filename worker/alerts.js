import { tailAlerts } from './monitor.js';
export default { async tail(events, env) { await tailAlerts(events, env); } };
