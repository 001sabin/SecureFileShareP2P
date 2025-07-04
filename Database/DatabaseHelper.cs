using Microsoft.EntityFrameworkCore;

namespace SecureFileShareP2P.Database
{
    public static class DatabaseHelper
    {
        public static void Initialize()
        {
            using (var db = new AppDbContext())
            {
                db.Database.EnsureCreated();  // Auto-creates DB
            }
        }
    }
}