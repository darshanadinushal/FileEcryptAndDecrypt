using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace EcryptAndDecrypt.Controllers
{
    public class AESController : Controller
    {
        private static IWebHostEnvironment _hostEnvironment;

        public AESController(IWebHostEnvironment environment)
        {
            _hostEnvironment = environment;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
