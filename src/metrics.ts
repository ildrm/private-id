export class Metrics {
  private routes = new Map<
    string,
    {
      requests: number;
      errors: number;
      milliseconds: number;
      maximumMilliseconds: number;
    }
  >();
  observe(route: string, status: number, milliseconds: number) {
    const value = this.routes.get(route) ?? {
      requests: 0,
      errors: 0,
      milliseconds: 0,
      maximumMilliseconds: 0,
    };
    value.requests++;
    if (status >= 500) value.errors++;
    value.milliseconds += milliseconds;
    value.maximumMilliseconds = Math.max(
      value.maximumMilliseconds,
      milliseconds,
    );
    this.routes.set(route, value);
  }
  snapshot() {
    return {
      scope: "this process since startup",
      routes: [...this.routes].map(([route, value]) => ({
        route,
        requests: value.requests,
        errors: value.errors,
        meanMilliseconds: value.milliseconds / value.requests,
        maximumMilliseconds: value.maximumMilliseconds,
      })),
    };
  }
}
