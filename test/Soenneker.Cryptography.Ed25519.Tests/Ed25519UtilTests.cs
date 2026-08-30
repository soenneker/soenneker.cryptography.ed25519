using System;
using System.Threading.Tasks;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Cryptography.Ed25519.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class Ed25519UtilTests : HostedUnitTest
{

    public Ed25519UtilTests(Host host) : base(host)
    {
    }

    [Test]
    public async Task VerifiesRfc8032TestVector()
    {
        byte[] publicKey = Convert.FromHexString("3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C");
        byte[] signature = Convert.FromHexString(
            "92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C00");

        bool valid = Ed25519Util.Verify(Convert.ToBase64String(publicKey), Convert.ToBase64String(signature), [0x72]);

        await Assert.That(valid).IsTrue();
    }
}
