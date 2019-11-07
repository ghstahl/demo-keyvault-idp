using FluentAssertions;
using KeyVaultBackground;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using Xunit;

namespace XUnitTest_JWT
{
  
    public class UnitTest_ECDSAConfig
    {
        const string ConfigS = @"{
	'Set': [{
		'PublicKey': 'RUNTMSAAAABkJ+1hvS4nTxp9bFdYFjucOd4dYqP5/8KC/FGrTLx98GOtvK+Duk5BYsLoWm+XhHARsdQmIPwrc5IHF8Rb9u0z',
		'PrivateKey': 'RUNTMiAAAABkJ+1hvS4nTxp9bFdYFjucOd4dYqP5/8KC/FGrTLx98GOtvK+Duk5BYsLoWm+XhHARsdQmIPwrc5IHF8Rb9u0zju9MRolikBop7a8ZjImxiEgmgC/nWmydJeHV7i3LOCY=',
		'NotBefore': '2019-11-07T21:07:00Z',
		'Expiration': '2019-11-17T21:08:00Z'
	}, {
		'PublicKey': 'RUNTMSAAAAAXxf5dx7UYBc6/lXrsfwZtliSuP6r7pFWlsukqb1UOcwQ2ojGgkmhZlDkWkLz7YIwRi3E6uU3VAKRSxn58q5iQ',
		'PrivateKey': 'RUNTMiAAAAAXxf5dx7UYBc6/lXrsfwZtliSuP6r7pFWlsukqb1UOcwQ2ojGgkmhZlDkWkLz7YIwRi3E6uU3VAKRSxn58q5iQmfyduiKhIsaNhpUNd9XHT6WTiYOqUgWTHf9z+WHlxM8=',
		'NotBefore': '2019-11-07T22:07:00Z',
		'Expiration': '2019-12-17T21:08:00Z'
	}]
}";

        string GuidS => Guid.NewGuid().ToString("N");

        [Fact]

        public void JWT_Ecdsa_Microsoft()
        {
            EDCSAConfigSet eDCSAConfigSet = new EDCSAConfigSet
            {
                Set = new List<EDCSAConfig>
                {
                   
                }
            };

            for (int i = 0; i < 2; i++)
            {

                var (privateKey, publicKey, _) = ECDsaMicrosoft.ECDSA.GenerateKeys("auth-code");
                eDCSAConfigSet.Set.Add(new EDCSAConfig
                {
                    PrivateKey = privateKey,
                    PublicKey = publicKey,
                    NotBefore = DateTime.UtcNow,
                    Expiration = DateTime.UtcNow.AddDays(10)
                });
            }

            var got = JsonConvert.DeserializeObject<EDCSAConfigSet>(ConfigS);
            var json = JsonConvert.SerializeObject(eDCSAConfigSet);
            got = JsonConvert.DeserializeObject<EDCSAConfigSet>(json);
            got.Set[0].PrivateKey.Should().BeEquivalentTo(eDCSAConfigSet.Set[0].PrivateKey);
            got.Set[0].PublicKey.Should().BeEquivalentTo(eDCSAConfigSet.Set[0].PublicKey);
            got.Set[0].NotBefore.Should().BeSameDateAs(eDCSAConfigSet.Set[0].NotBefore);
            got.Set[0].Expiration.Should().BeSameDateAs(eDCSAConfigSet.Set[0].Expiration);

        }
    }
}
