FROM eclipse-temurin:21-jdk-jammy AS build
WORKDIR /workspace

COPY gradlew gradle.properties settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY src/main ./src/main
RUN chmod +x gradlew
RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon installDist --console=plain

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /workspace/build/install/SSC_workAssignment/ ./
RUN mkdir -p /app/config /app/media

ENTRYPOINT ["/app/bin/SSC_workAssignment"]
