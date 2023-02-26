using System.ComponentModel.DataAnnotations;

namespace Login.API.Models.Authentication.SignUp
{
    public class ResetPassword
    {

        [Required]
        public string? Password { get; set; }

        [Compare("Password", ErrorMessage = "The password and cnfirmation password do not match")]
        public string? ConfirmPassword { get; set; }

        public string? Token { get; set; }
        public string? Email { get; set; }
    }
}