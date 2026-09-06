// Public room IDs, provisioned by the operator out of band. No self-admission.
export function allowedRooms(value = '') {
  const rooms = String(value).split(',').map(s => s.trim()).filter(Boolean);
  if (rooms.length > 256 || rooms.some(s => !/^[A-Za-z0-9_-]{22}$/.test(s))) throw new Error('Invalid ALLOWED_ROOMS (maximum 256 exact room IDs)');
  return rooms;
}
export function admitted(config, roomId) {
  return Array.isArray(config.allowedRooms) && config.allowedRooms.includes(roomId);
}
