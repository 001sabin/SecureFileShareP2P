using Microsoft.EntityFrameworkCore;
using SecureFileShareP2P.Models;  // Reference Models namespace

namespace SecureFileShareP2P.Database  // Match your folder
{
    public class AppDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseSqlite("Data Source=SecureFileShare.db");
        }
    }
}