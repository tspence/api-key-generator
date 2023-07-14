using ApiKeyGenerator.Benchmarks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace ApiKeyGenerator.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<AlgorithmBenchmarks>();
        }
    }
}