import { LocalChromeSink } from "./localChrome.js";
import { BrowserUseSink } from "./browserUse.js";
import { FileDropSink } from "./fileDrop.js";
import { RelaySink } from "./relay.js";

/** Build the sink registry. Sinks self-register here by id. */
export function buildRegistry(opts = {}) {
  const sinks = [new LocalChromeSink(), new FileDropSink(), new RelaySink(), new BrowserUseSink(opts.fetchImpl)];
  const byId = new Map(sinks.map((s) => [s.id, s]));
  return {
    all: () => sinks,
    get: (id) => byId.get(id),
  };
}
