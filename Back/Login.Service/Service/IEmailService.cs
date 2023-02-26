using Login.Service.Models;

namespace Login.Service.Service
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}