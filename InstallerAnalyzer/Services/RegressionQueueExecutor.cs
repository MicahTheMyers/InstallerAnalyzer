namespace InstallerAnalyzer.Services;

// Queue sequencing is independent of WPF and of the mechanism used to start a run.
// A future scheduler can invoke the same executor; no background schedule is created here.
public static class RegressionQueueExecutor
{
    public static async Task ExecuteAsync<T>(IEnumerable<T> items, Func<T, CancellationToken, Task> execute, CancellationToken cancellationToken)
    {
        var snapshot = items.ToArray();
        foreach (var item in snapshot)
        {
            if (cancellationToken.IsCancellationRequested) break;
            await execute(item, cancellationToken);
        }
    }
}
