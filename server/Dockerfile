FROM node:22-alpine

RUN addgroup -S chromesync && adduser -S -G chromesync chromesync \
  && mkdir -p /var/lib/chromesync-relay \
  && chown chromesync:chromesync /var/lib/chromesync-relay

WORKDIR /app
COPY server.js auth.js store.js ratelimit.js config.js ./

ENV HOST=0.0.0.0
ENV PORT=8787
ENV DATA_DIR=/var/lib/chromesync-relay

USER chromesync
EXPOSE 8787
VOLUME ["/var/lib/chromesync-relay"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
