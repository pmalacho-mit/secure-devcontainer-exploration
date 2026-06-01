FROM node:22-bookworm-slim

ARG BROWSER=chrome
ENV BROWSER=$BROWSER

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

ENV PATH="/app/node_modules/.bin:$PATH"

RUN npx playwright install --with-deps "$BROWSER"
RUN playwright-cli install-browser "$BROWSER"

CMD ["bash"]