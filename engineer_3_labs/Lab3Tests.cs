using NUnit.Framework;
using IIG.PasswordHashingUtils;


namespace tests3
{
    [TestFixture]
    public class Tests3
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
        public void CheckHashWithMaxAllowedAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 2147483647); // 2,147,483,647 is boundary value

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
        public void CheckHashWithSalt()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, "some_salt");

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashLessThanZeroAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 0);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithSaltAndAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, "salt", adlerMod32: 1000);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithNonASCIIChars()
        {
            // Arrange
            string pw = ".இந்தியா";

            // Act 
            string hash = PasswordHasher.GetHash(pw);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }

        [Test]
        public void CheckHashWithBlankPassword()
        {
            // Arrange
            string pw = "";

            // Act 
            string hash = PasswordHasher.GetHash(pw);

            // Assert
            Assert.AreEqual(hash.Length, 64);
        }
    }
}
