# JwtBearerTokenAuth

1. Создадим пустой проект ASP.Net Core (Let's create new empty ASP.Net Core project)

2. Добавим папку Models и определим класс Person, который описывает учетные записи пользователей в приложении (Add folder Models and define Person class, and declare user accounts)

    public class Person
    {
        public string Login { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }

3. Для работы с JWT-токенами установим через Nuget пакет Microsoft.AspNetCore.Authentication.JwtBearer. (Install JwtBearer to work with JWT-tokens)

4. Добавим специальный класс AuthOptions? который описывает несколько свойств для генерации токена. (Add class AuthOpions to declare some properties for token generating)

    public class AuthOptions
    {
        public const string ISSUER = "MyAuthServer"; // издатель токена
        public const string AUDIENCE = "MyAuthClient"; // потребитель токена
        const string KEY = "mysupersecret_secretkey!123";   // ключ для шифрации
        public const int LIFETIME = 1; // время жизни токена - 1 минута
        public static SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            return new SymmetricSecurityKey(Encoding.ASCII.GetBytes(KEY));
        }
    }
    
5. Изменим класс Startup следующим образом. (Let's change Startup class as follows)

    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                    .AddJwtBearer(options =>
                    {
                        options.RequireHttpsMetadata = false;
                        options.TokenValidationParameters = new TokenValidationParameters
                        {
                            // укзывает, будет ли валидироваться издатель при валидации токена
                            ValidateIssuer = true,
                            // строка, представляющая издателя
                            ValidIssuer = AuthOptions.ISSUER,
 
                            // будет ли валидироваться потребитель токена
                            ValidateAudience = true,
                            // установка потребителя токена
                            ValidAudience = AuthOptions.AUDIENCE,
                            // будет ли валидироваться время существования
                            ValidateLifetime = true,
 
                            // установка ключа безопасности
                            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                            // валидация ключа безопасности
                            ValidateIssuerSigningKey = true,
                        };
                    });
            services.AddControllersWithViews();
        }
 
        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
 
            app.UseDefaultFiles();
            app.UseStaticFiles();
 
            app.UseRouting();
 
            app.UseAuthentication();
            app.UseAuthorization();
 
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }

6. Создаем в проекте папку Controllers и добавим новый контроллер AccountController. (Create a Controllers folder and add new controller AccountController)
    
    public class AccountController : Controller
    {
        // тестовые данные вместо использования базы данных
        // test data instead of using database
        private List<Person> people = new List<Person>
        {
            new Person {Login="admin@gmail.com", Password="12345", Role = "admin" },
            new Person { Login="qwerty@gmail.com", Password="55555", Role = "user" }
        };
 
        [HttpPost("/token")]
        public IActionResult Token(string username, string password)
        {
            var identity = GetIdentity(username, password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Invalid username or password." });
            }
 
            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                    issuer: AuthOptions.ISSUER,
                    audience: AuthOptions.AUDIENCE,
                    notBefore: now,
                    claims: identity.Claims,
                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
 
            var response = new
            {
                access_token = encodedJwt,
                username = identity.Name
            };
 
            return Json(response);
        }
 
        private ClaimsIdentity GetIdentity(string username, string password)
        {
            Person person = people.FirstOrDefault(x => x.Login == username && x.Password == password);
            if (person != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, person.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, person.Role)
                };
                ClaimsIdentity claimsIdentity =
                new ClaimsIdentity(claims, "Token", ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }
 
            // если пользователя не найдено
            // if no user is found
            return null;
        }
    }
  
7.  Для тестирования токена создадим простой контроллер ValuesController. (To test the token, let's create a simple controller ValuesController)
    
    [ApiController]
    [Route("api/[controller]")]
    public class ValuesController : Controller
    {
        [Authorize]
        [Route("getlogin")]
        public IActionResult GetLogin()
        {
            return Ok($"Ваш логин: {User.Identity.Name}");
        }
         
        [Authorize(Roles = "admin")]
        [Route("getrole")]
        public IActionResult GetRole()
        {
            return Ok("Ваша роль: администратор");
        }
    }
  
8. И в конце добавим папку wwwroot, и новый файл index.html. (And at the end add wwwroot folder, and a new index.html file)
  
  &lt;!DOCTYPE html&gt;
  &lt;html&gt;
  &lt;head&gt;
      &lt;meta charset="utf-8" /&gt;
      &lt;title&gt;JWT в ASP.NET Core Web API&lt;/title&gt;
  &lt;/head&gt;
  &lt;body&gt;
      &lt;div id="userInfo" style="display:none;"&gt;
          &lt;p&gt;Вы вошли как: &lt;span id="userName"&gt;&lt;/span&gt;&lt;/p&gt;
          &lt;input type="button" value="Выйти" id="logOut" /&gt;
      &lt;/div&gt;
      &lt;div id="loginForm"&gt;
          &lt;h3&gt;Вход на сайт&lt;/h3&gt;
          &lt;label&gt;Введите email&lt;/label&gt;&lt;br /&gt;
          &lt;input type="email" id="emailLogin" /&gt; &lt;br /&gt;&lt;br /&gt;
          &lt;label&gt;Введите пароль&lt;/label&gt;&lt;br /&gt;
          &lt;input type="password" id="passwordLogin" /&gt;&lt;br /&gt;&lt;br /&gt;
          &lt;input type="submit" id="submitLogin" value="Логин" /&gt;
      &lt;/div&gt;
      &lt;div&gt;
          &lt;input type="submit" id="getDataByLogin" value="Данные по логину" /&gt;
      &lt;/div&gt;
      &lt;div&gt;
          &lt;input type="submit" id="getDataByRole" value="Данные по роли" /&gt;
      &lt;/div&gt;

      &lt;script&gt;
          var tokenKey = "accessToken";

          // отпавка запроса к контроллеру AccountController для получения токена
          async function getTokenAsync() {

              // получаем данные формы и фомируем объект для отправки
              const formData = new FormData();
              formData.append("grant_type", "password");
              formData.append("username", document.getElementById("emailLogin").value);
              formData.append("password", document.getElementById("passwordLogin").value);

              // отправляет запрос и получаем ответ
              const response = await fetch("/token", {
                  method: "POST",
                  headers: {"Accept": "application/json"},
                  body: formData
              });
              // получаем данные 
              const data = await response.json();

              // если запрос прошел нормально
              if (response.ok === true) {

                  // изменяем содержимое и видимость блоков на странице
                  document.getElementById("userName").innerText = data.username;
                  document.getElementById("userInfo").style.display = "block";
                  document.getElementById("loginForm").style.display = "none";
                  // сохраняем в хранилище sessionStorage токен доступа
                  sessionStorage.setItem(tokenKey, data.access_token);
                  console.log(data.access_token);
               }
              else {
                  // если произошла ошибка, из errorText получаем текст ошибки
                  console.log("Error: ", response.status, data.errorText);
              }
          };
          // отправка запроса к контроллеру ValuesController
          async function getData(url) {
              const token = sessionStorage.getItem(tokenKey);

              const response = await fetch(url, {
                  method: "GET",
                  headers: {
                      "Accept": "application/json",
                      "Authorization": "Bearer " + token  // передача токена в заголовке
                  }
              });
              if (response.ok === true) {

                  const data = await response.json();
                  alert(data)
              }
              else
                  console.log("Status: ", response.status);
          };

          // получаем токен
          document.getElementById("submitLogin").addEventListener("click", e =&gt; {

              e.preventDefault();
              getTokenAsync();
          });

          // условный выход - просто удаляем токен и меняем видимость блоков
          document.getElementById("logOut").addEventListener("click", e =&gt; {

              e.preventDefault();
              document.getElementById("userName").innerText = "";
              document.getElementById("userInfo").style.display = "none";
              document.getElementById("loginForm").style.display = "block";
              sessionStorage.removeItem(tokenKey);
          });


          // кнопка получения имя пользователя  - /api/values/getlogin
          document.getElementById("getDataByLogin").addEventListener("click", e =&gt; {

              e.preventDefault();
              getData("/api/values/getlogin");
          });

          // кнопка получения роли  - /api/values/getrole
          document.getElementById("getDataByRole").addEventListener("click", e =&gt; {

              e.preventDefault();
              getData("/api/values/getrole");
          });
      &lt;/script&gt;
  &lt;/body&gt;
  &lt;/html&gt;
