using Microsoft.EntityFrameworkCore;
using VaultStore.Models;

namespace VaultStore.Database
{
    public class VaultDbContext : DbContext
    {
        public VaultDbContext (DbContextOptions<VaultDbContext> options): base(options)
        {
        }

        public DbSet<FileModel> File { get; set; }
        public DbSet<UserModel> User { get; set; }
        public DbSet<StorageModel> Storage { get; set; }
    }
}