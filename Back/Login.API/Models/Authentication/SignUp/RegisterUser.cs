using System.ComponentModel.DataAnnotations;

namespace Login.API.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required]
        public string? Username { get; set; }

        [Required]
        public string? Password { get; set; }

        [Required]
        [EmailAddress]
        public string? Email { get; set; }
    }
}