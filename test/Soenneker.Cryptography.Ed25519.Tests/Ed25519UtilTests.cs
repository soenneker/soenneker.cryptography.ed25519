using Soenneker.Tests.HostedUnit;

namespace Soenneker.Cryptography.Ed25519.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class Ed25519UtilTests : HostedUnitTest
{

    public Ed25519UtilTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {

    }
}
