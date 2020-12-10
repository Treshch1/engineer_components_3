using System;
using NUnit.Framework;


namespace IIG.PasswordHashingUtils
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
            Assert.AreNotEqual(pw, hash);
        }

        [Test]
        public void CheckHashWithAdlerMoreThanAllowed()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 2147483648); // 2,147,483,647 is boundary value

            // Assert
            Assert.AreNotEqual(pw, hash);
        }

        [Test]
        public void CheckHashWithSalt()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, "some_salt");

            // Assert
            Assert.AreNotEqual(pw, hash);
        }

        [Test]
        public void CheckHashLessThanZeroAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, adlerMod32: 0);

            // Assert
            Assert.AreNotEqual(pw, hash);
        }

        [Test]
        public void CheckHashWithSaltAndAdler()
        {
            // Arrange
            string pw = "qqweqqwe";

            // Act 
            string hash = PasswordHasher.GetHash(pw, "salt", 0);
            Console.WriteLine(hash.Length);
            // Assert
            Assert.AreEqual(hash.Length, 1);
        }
    }
}
