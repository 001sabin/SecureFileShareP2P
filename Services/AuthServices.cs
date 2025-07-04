using SecureFileShareP2P.Cryptography;
using SecureFileShareP2P.Database;
using SecureFileShareP2P.Models;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileShareP2P.Services
{
    public static class AuthService
    {
        // Generate a random salt (16 bytes)
        public static string GenerateSalt()
        {
            byte[] saltBytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        // Manual SHA-256 hashing with salt
        public static string HashPassword(string password, string salt)
        {
            string saltedPassword = password + salt;
            return SHA256Hasher.ComputeHash(saltedPassword);
        }

        // Register a new user
        public static bool Register(string username, string password)
        {
            using (var db = new AppDbContext())
            {
                if (db.Users.Any(u => u.Username == username))
                    return false; // Username exists

                string salt = GenerateSalt();
                string hashedPassword = HashPassword(password, salt);

                db.Users.Add(new User
                {
                    Username = username,
                    PasswordHash = hashedPassword,
                    Salt = salt
                });
                db.SaveChanges();
                return true;
            }
        }

        // Validate login credentials
        public static bool Login(string username, string password)
        {
            using (var db = new AppDbContext())
            {
                User user = db.Users.FirstOrDefault(u => u.Username == username);
                if (user == null) return false;

                string hashedInput = HashPassword(password, user.Salt);
                return hashedInput == user.PasswordHash;
            }
        }
    }
}