using System;
using NUnit.Framework;
using IIG.PasswordHashingUtils;


namespace engineer_3_labs
{
    [TestFixture]
    public class Tests1
    {
        [Test]
        public void CheckHashIsGenated()
        {
            // Arrange
            string pw = "qqweqqwe";

             // Act 
            string hash = PasswordHasher.GetHash(pw);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithEmptyStringPassword()
        {
            // Arrange
            string pw = "";

            // Act 
            string hash = PasswordHasher.GetHash(pw);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithSpecialSymbolsPassword()
        {
            // Arrange
            string pw = "!@#$%^&*()";

            // Act 
            string hash = PasswordHasher.GetHash(pw);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithNullPassword()
        {
            // Arrange
            string pw = null;

            // Act 
            try {
                string hash = PasswordHasher.GetHash(pw);
                Assert.Fail();
            } catch (ArgumentNullException e) {
                // Assert
                Assert.Pass();
            }
        }

        [Test]
        public void CheckHashWithSalt()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, salt: "somesalt");

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 1);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithZeroAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 0);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithAdlerMoreThanAllowed()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 2147483648); // 2,147,483,647 is boundary value

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithAdlerAndSalt()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, salt: "anything", adlerMod32: 45);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }
    }
}
