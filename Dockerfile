# ---- build
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -ntp dependency:go-offline
COPY src src
RUN mvn -B -ntp package -DskipTests

# ---- run
FROM eclipse-temurin:21-jre
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system app && useradd --system --gid app --no-create-home app
WORKDIR /app
COPY --from=build /src/target/snap-sim.jar app.jar
USER app
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fs "http://localhost:${PORT:-8080}/api/health" || exit 1
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "/app/app.jar"]
