# Use official Node.js image
FROM node:20-bookworm AS build
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source
COPY . ./

# Build the project
RUN npm run build

# --- Serve the build output with a lightweight HTTP server ---
FROM node:20-bookworm AS runner
WORKDIR /app

# Install serve for production preview
RUN npm install -g serve

# Copy built files
COPY --from=build /app/dist /app/dist

# Expose default port
EXPOSE 3000

# Serve built files
CMD ["serve", "-s", "dist", "-l", "3000"]

