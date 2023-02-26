using System.ComponentModel.DataAnnotations;

namespace Login.API.Models.Authentication.Login
{
    public class LoginUser
    {
        [Required]
        public string? Username { get; set; }

        [Required]
        public string? Password { get; set; }
    }
}