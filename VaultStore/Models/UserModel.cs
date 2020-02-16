using System;

namespace VaultStore.Models
{
    public class UserModel
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Certificate { get; set; }
        public string PasswordHash { get; set; }
    }
}