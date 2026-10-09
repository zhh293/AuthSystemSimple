FROM eclipse-temurin:17-jre-jammy

WORKDIR /app
COPY sso-server/target/sso-server-0.1.0-SNAPSHOT.jar /app/sso-server.jar
RUN groupadd --system --gid 10001 sso && useradd --system --uid 10001 --gid 10001 --home-dir /app --shell /usr/sbin/nologin sso \
    && chown -R sso:sso /app

EXPOSE 8080 50051
USER 10001:10001
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/sso-server.jar"]
