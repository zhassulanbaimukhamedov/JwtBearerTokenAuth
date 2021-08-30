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
  <pre class="prettyprint linenums prettyprinted" style=""><ol class="linenums"><li class="L0"><code class="lang-html"><span class="dec">&lt;!DOCTYPE html&gt;</span></code></li><li class="L1"><code class="lang-html"><span class="tag">&lt;html&gt;</span></code></li><li class="L2"><code class="lang-html"><span class="tag">&lt;head&gt;</span></code></li><li class="L3"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;meta</span><span class="pln"> </span><span class="atn">charset</span><span class="pun">=</span><span class="atv">"utf-8"</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L4"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;title&gt;</span><span class="pln">JWT в ASP.NET Core Web API</span><span class="tag">&lt;/title&gt;</span></code></li><li class="L5"><code class="lang-html"><span class="tag">&lt;/head&gt;</span></code></li><li class="L6"><code class="lang-html"><span class="tag">&lt;body&gt;</span></code></li><li class="L7"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;div</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"userInfo"</span><span class="pln"> </span><span class="atn">style</span><span class="pun">=</span><span class="atv">"</span><span class="pln">display</span><span class="pun">:</span><span class="pln">none</span><span class="pun">;</span><span class="atv">"</span><span class="tag">&gt;</span></code></li><li class="L8"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;p&gt;</span><span class="pln">Вы вошли как: </span><span class="tag">&lt;span</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"userName"</span><span class="tag">&gt;&lt;/span&gt;&lt;/p&gt;</span></code></li><li class="L9"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"button"</span><span class="pln"> </span><span class="atn">value</span><span class="pun">=</span><span class="atv">"Выйти"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"logOut"</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L0"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;/div&gt;</span></code></li><li class="L1"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;div</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"loginForm"</span><span class="tag">&gt;</span></code></li><li class="L2"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;h3&gt;</span><span class="pln">Вход на сайт</span><span class="tag">&lt;/h3&gt;</span></code></li><li class="L3"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;label&gt;</span><span class="pln">Введите email</span><span class="tag">&lt;/label&gt;&lt;br</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L4"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"email"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"emailLogin"</span><span class="pln"> </span><span class="tag">/&gt;</span><span class="pln"> </span><span class="tag">&lt;br</span><span class="pln"> </span><span class="tag">/&gt;&lt;br</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L5"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;label&gt;</span><span class="pln">Введите пароль</span><span class="tag">&lt;/label&gt;&lt;br</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L6"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"password"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"passwordLogin"</span><span class="pln"> </span><span class="tag">/&gt;&lt;br</span><span class="pln"> </span><span class="tag">/&gt;&lt;br</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L7"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"submit"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"submitLogin"</span><span class="pln"> </span><span class="atn">value</span><span class="pun">=</span><span class="atv">"Логин"</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L8"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;/div&gt;</span></code></li><li class="L9"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;div&gt;</span></code></li><li class="L0"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"submit"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"getDataByLogin"</span><span class="pln"> </span><span class="atn">value</span><span class="pun">=</span><span class="atv">"Данные по логину"</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L1"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;/div&gt;</span></code></li><li class="L2"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;div&gt;</span></code></li><li class="L3"><code class="lang-html"><span class="pln">        </span><span class="tag">&lt;input</span><span class="pln"> </span><span class="atn">type</span><span class="pun">=</span><span class="atv">"submit"</span><span class="pln"> </span><span class="atn">id</span><span class="pun">=</span><span class="atv">"getDataByRole"</span><span class="pln"> </span><span class="atn">value</span><span class="pun">=</span><span class="atv">"Данные по роли"</span><span class="pln"> </span><span class="tag">/&gt;</span></code></li><li class="L4"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;/div&gt;</span></code></li><li class="L5"><code class="lang-html"></code></li><li class="L6"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;script&gt;</span></code></li><li class="L7"><code class="lang-html"><span class="pln">        </span><span class="kwd">var</span><span class="pln"> tokenKey </span><span class="pun">=</span><span class="pln"> </span><span class="str">"accessToken"</span><span class="pun">;</span></code></li><li class="L8"><code class="lang-html"></code></li><li class="L9"><code class="lang-html"><span class="pln">        </span><span class="com">// отпавка запроса к контроллеру AccountController для получения токена</span></code></li><li class="L0"><code class="lang-html"><span class="pln">        async </span><span class="kwd">function</span><span class="pln"> getTokenAsync</span><span class="pun">()</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L1"><code class="lang-html"></code></li><li class="L2"><code class="lang-html"><span class="pln">            </span><span class="com">// получаем данные формы и фомируем объект для отправки</span></code></li><li class="L3"><code class="lang-html"><span class="pln">            </span><span class="kwd">const</span><span class="pln"> formData </span><span class="pun">=</span><span class="pln"> </span><span class="kwd">new</span><span class="pln"> </span><span class="typ">FormData</span><span class="pun">();</span></code></li><li class="L4"><code class="lang-html"><span class="pln">            formData</span><span class="pun">.</span><span class="pln">append</span><span class="pun">(</span><span class="str">"grant_type"</span><span class="pun">,</span><span class="pln"> </span><span class="str">"password"</span><span class="pun">);</span></code></li><li class="L5"><code class="lang-html"><span class="pln">            formData</span><span class="pun">.</span><span class="pln">append</span><span class="pun">(</span><span class="str">"username"</span><span class="pun">,</span><span class="pln"> document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"emailLogin"</span><span class="pun">).</span><span class="pln">value</span><span class="pun">);</span></code></li><li class="L6"><code class="lang-html"><span class="pln">            formData</span><span class="pun">.</span><span class="pln">append</span><span class="pun">(</span><span class="str">"password"</span><span class="pun">,</span><span class="pln"> document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"passwordLogin"</span><span class="pun">).</span><span class="pln">value</span><span class="pun">);</span></code></li><li class="L7"><code class="lang-html"></code></li><li class="L8"><code class="lang-html"><span class="pln">            </span><span class="com">// отправляет запрос и получаем ответ</span></code></li><li class="L9"><code class="lang-html"><span class="pln">            </span><span class="kwd">const</span><span class="pln"> response </span><span class="pun">=</span><span class="pln"> await fetch</span><span class="pun">(</span><span class="str">"/token"</span><span class="pun">,</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L0"><code class="lang-html"><span class="pln">                method</span><span class="pun">:</span><span class="pln"> </span><span class="str">"POST"</span><span class="pun">,</span></code></li><li class="L1"><code class="lang-html"><span class="pln">                headers</span><span class="pun">:</span><span class="pln"> </span><span class="pun">{</span><span class="str">"Accept"</span><span class="pun">:</span><span class="pln"> </span><span class="str">"application/json"</span><span class="pun">},</span></code></li><li class="L2"><code class="lang-html"><span class="pln">                body</span><span class="pun">:</span><span class="pln"> formData</span></code></li><li class="L3"><code class="lang-html"><span class="pln">            </span><span class="pun">});</span></code></li><li class="L4"><code class="lang-html"><span class="pln">            </span><span class="com">// получаем данные </span></code></li><li class="L5"><code class="lang-html"><span class="pln">            </span><span class="kwd">const</span><span class="pln"> data </span><span class="pun">=</span><span class="pln"> await response</span><span class="pun">.</span><span class="pln">json</span><span class="pun">();</span></code></li><li class="L6"><code class="lang-html"></code></li><li class="L7"><code class="lang-html"><span class="pln">            </span><span class="com">// если запрос прошел нормально</span></code></li><li class="L8"><code class="lang-html"><span class="pln">            </span><span class="kwd">if</span><span class="pln"> </span><span class="pun">(</span><span class="pln">response</span><span class="pun">.</span><span class="pln">ok </span><span class="pun">===</span><span class="pln"> </span><span class="kwd">true</span><span class="pun">)</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L9"><code class="lang-html"></code></li><li class="L0"><code class="lang-html"><span class="pln">                </span><span class="com">// изменяем содержимое и видимость блоков на странице</span></code></li><li class="L1"><code class="lang-html"><span class="pln">                document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"userName"</span><span class="pun">).</span><span class="pln">innerText </span><span class="pun">=</span><span class="pln"> data</span><span class="pun">.</span><span class="pln">username</span><span class="pun">;</span></code></li><li class="L2"><code class="lang-html"><span class="pln">                document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"userInfo"</span><span class="pun">).</span><span class="pln">style</span><span class="pun">.</span><span class="pln">display </span><span class="pun">=</span><span class="pln"> </span><span class="str">"block"</span><span class="pun">;</span></code></li><li class="L3"><code class="lang-html"><span class="pln">                document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"loginForm"</span><span class="pun">).</span><span class="pln">style</span><span class="pun">.</span><span class="pln">display </span><span class="pun">=</span><span class="pln"> </span><span class="str">"none"</span><span class="pun">;</span></code></li><li class="L4"><code class="lang-html"><span class="pln">                </span><span class="com">// сохраняем в хранилище sessionStorage токен доступа</span></code></li><li class="L5"><code class="lang-html"><span class="pln">                sessionStorage</span><span class="pun">.</span><span class="pln">setItem</span><span class="pun">(</span><span class="pln">tokenKey</span><span class="pun">,</span><span class="pln"> data</span><span class="pun">.</span><span class="pln">access_token</span><span class="pun">);</span></code></li><li class="L6"><code class="lang-html"><span class="pln">                console</span><span class="pun">.</span><span class="pln">log</span><span class="pun">(</span><span class="pln">data</span><span class="pun">.</span><span class="pln">access_token</span><span class="pun">);</span></code></li><li class="L7"><code class="lang-html"><span class="pln">             </span><span class="pun">}</span></code></li><li class="L8"><code class="lang-html"><span class="pln">            </span><span class="kwd">else</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L9"><code class="lang-html"><span class="pln">                </span><span class="com">// если произошла ошибка, из errorText получаем текст ошибки</span></code></li><li class="L0"><code class="lang-html"><span class="pln">                console</span><span class="pun">.</span><span class="pln">log</span><span class="pun">(</span><span class="str">"Error: "</span><span class="pun">,</span><span class="pln"> response</span><span class="pun">.</span><span class="pln">status</span><span class="pun">,</span><span class="pln"> data</span><span class="pun">.</span><span class="pln">errorText</span><span class="pun">);</span></code></li><li class="L1"><code class="lang-html"><span class="pln">            </span><span class="pun">}</span></code></li><li class="L2"><code class="lang-html"><span class="pln">        </span><span class="pun">};</span></code></li><li class="L3"><code class="lang-html"><span class="pln">        </span><span class="com">// отправка запроса к контроллеру ValuesController</span></code></li><li class="L4"><code class="lang-html"><span class="pln">        async </span><span class="kwd">function</span><span class="pln"> getData</span><span class="pun">(</span><span class="pln">url</span><span class="pun">)</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L5"><code class="lang-html"><span class="pln">            </span><span class="kwd">const</span><span class="pln"> token </span><span class="pun">=</span><span class="pln"> sessionStorage</span><span class="pun">.</span><span class="pln">getItem</span><span class="pun">(</span><span class="pln">tokenKey</span><span class="pun">);</span></code></li><li class="L6"><code class="lang-html"></code></li><li class="L7"><code class="lang-html"><span class="pln">            </span><span class="kwd">const</span><span class="pln"> response </span><span class="pun">=</span><span class="pln"> await fetch</span><span class="pun">(</span><span class="pln">url</span><span class="pun">,</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L8"><code class="lang-html"><span class="pln">                method</span><span class="pun">:</span><span class="pln"> </span><span class="str">"GET"</span><span class="pun">,</span></code></li><li class="L9"><code class="lang-html"><span class="pln">                headers</span><span class="pun">:</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L0"><code class="lang-html"><span class="pln">                    </span><span class="str">"Accept"</span><span class="pun">:</span><span class="pln"> </span><span class="str">"application/json"</span><span class="pun">,</span></code></li><li class="L1"><code class="lang-html"><span class="pln">                    </span><span class="str">"Authorization"</span><span class="pun">:</span><span class="pln"> </span><span class="str">"Bearer "</span><span class="pln"> </span><span class="pun">+</span><span class="pln"> token  </span><span class="com">// передача токена в заголовке</span></code></li><li class="L2"><code class="lang-html"><span class="pln">                </span><span class="pun">}</span></code></li><li class="L3"><code class="lang-html"><span class="pln">            </span><span class="pun">});</span></code></li><li class="L4"><code class="lang-html"><span class="pln">            </span><span class="kwd">if</span><span class="pln"> </span><span class="pun">(</span><span class="pln">response</span><span class="pun">.</span><span class="pln">ok </span><span class="pun">===</span><span class="pln"> </span><span class="kwd">true</span><span class="pun">)</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L5"><code class="lang-html"></code></li><li class="L6"><code class="lang-html"><span class="pln">                </span><span class="kwd">const</span><span class="pln"> data </span><span class="pun">=</span><span class="pln"> await response</span><span class="pun">.</span><span class="pln">json</span><span class="pun">();</span></code></li><li class="L7"><code class="lang-html"><span class="pln">                alert</span><span class="pun">(</span><span class="pln">data</span><span class="pun">)</span></code></li><li class="L8"><code class="lang-html"><span class="pln">            </span><span class="pun">}</span></code></li><li class="L9"><code class="lang-html"><span class="pln">            </span><span class="kwd">else</span></code></li><li class="L0"><code class="lang-html"><span class="pln">                console</span><span class="pun">.</span><span class="pln">log</span><span class="pun">(</span><span class="str">"Status: "</span><span class="pun">,</span><span class="pln"> response</span><span class="pun">.</span><span class="pln">status</span><span class="pun">);</span></code></li><li class="L1"><code class="lang-html"><span class="pln">        </span><span class="pun">};</span></code></li><li class="L2"><code class="lang-html"></code></li><li class="L3"><code class="lang-html"><span class="pln">        </span><span class="com">// получаем токен</span></code></li><li class="L4"><code class="lang-html"><span class="pln">        document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"submitLogin"</span><span class="pun">).</span><span class="pln">addEventListener</span><span class="pun">(</span><span class="str">"click"</span><span class="pun">,</span><span class="pln"> e </span><span class="pun">=&gt;</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L5"><code class="lang-html"></code></li><li class="L6"><code class="lang-html"><span class="pln">            e</span><span class="pun">.</span><span class="pln">preventDefault</span><span class="pun">();</span></code></li><li class="L7"><code class="lang-html"><span class="pln">            getTokenAsync</span><span class="pun">();</span></code></li><li class="L8"><code class="lang-html"><span class="pln">        </span><span class="pun">});</span></code></li><li class="L9"><code class="lang-html"></code></li><li class="L0"><code class="lang-html"><span class="pln">        </span><span class="com">// условный выход - просто удаляем токен и меняем видимость блоков</span></code></li><li class="L1"><code class="lang-html"><span class="pln">        document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"logOut"</span><span class="pun">).</span><span class="pln">addEventListener</span><span class="pun">(</span><span class="str">"click"</span><span class="pun">,</span><span class="pln"> e </span><span class="pun">=&gt;</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L2"><code class="lang-html"></code></li><li class="L3"><code class="lang-html"><span class="pln">            e</span><span class="pun">.</span><span class="pln">preventDefault</span><span class="pun">();</span></code></li><li class="L4"><code class="lang-html"><span class="pln">            document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"userName"</span><span class="pun">).</span><span class="pln">innerText </span><span class="pun">=</span><span class="pln"> </span><span class="str">""</span><span class="pun">;</span></code></li><li class="L5"><code class="lang-html"><span class="pln">            document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"userInfo"</span><span class="pun">).</span><span class="pln">style</span><span class="pun">.</span><span class="pln">display </span><span class="pun">=</span><span class="pln"> </span><span class="str">"none"</span><span class="pun">;</span></code></li><li class="L6"><code class="lang-html"><span class="pln">            document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"loginForm"</span><span class="pun">).</span><span class="pln">style</span><span class="pun">.</span><span class="pln">display </span><span class="pun">=</span><span class="pln"> </span><span class="str">"block"</span><span class="pun">;</span></code></li><li class="L7"><code class="lang-html"><span class="pln">            sessionStorage</span><span class="pun">.</span><span class="pln">removeItem</span><span class="pun">(</span><span class="pln">tokenKey</span><span class="pun">);</span></code></li><li class="L8"><code class="lang-html"><span class="pln">        </span><span class="pun">});</span></code></li><li class="L9"><code class="lang-html"></code></li><li class="L0"><code class="lang-html"></code></li><li class="L1"><code class="lang-html"><span class="pln">        </span><span class="com">// кнопка получения имя пользователя  - /api/values/getlogin</span></code></li><li class="L2"><code class="lang-html"><span class="pln">        document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"getDataByLogin"</span><span class="pun">).</span><span class="pln">addEventListener</span><span class="pun">(</span><span class="str">"click"</span><span class="pun">,</span><span class="pln"> e </span><span class="pun">=&gt;</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L3"><code class="lang-html"></code></li><li class="L4"><code class="lang-html"><span class="pln">            e</span><span class="pun">.</span><span class="pln">preventDefault</span><span class="pun">();</span></code></li><li class="L5"><code class="lang-html"><span class="pln">            getData</span><span class="pun">(</span><span class="str">"/api/values/getlogin"</span><span class="pun">);</span></code></li><li class="L6"><code class="lang-html"><span class="pln">        </span><span class="pun">});</span></code></li><li class="L7"><code class="lang-html"></code></li><li class="L8"><code class="lang-html"><span class="pln">        </span><span class="com">// кнопка получения роли  - /api/values/getrole</span></code></li><li class="L9"><code class="lang-html"><span class="pln">        document</span><span class="pun">.</span><span class="pln">getElementById</span><span class="pun">(</span><span class="str">"getDataByRole"</span><span class="pun">).</span><span class="pln">addEventListener</span><span class="pun">(</span><span class="str">"click"</span><span class="pun">,</span><span class="pln"> e </span><span class="pun">=&gt;</span><span class="pln"> </span><span class="pun">{</span></code></li><li class="L0"><code class="lang-html"></code></li><li class="L1"><code class="lang-html"><span class="pln">            e</span><span class="pun">.</span><span class="pln">preventDefault</span><span class="pun">();</span></code></li><li class="L2"><code class="lang-html"><span class="pln">            getData</span><span class="pun">(</span><span class="str">"/api/values/getrole"</span><span class="pun">);</span></code></li><li class="L3"><code class="lang-html"><span class="pln">        </span><span class="pun">});</span></code></li><li class="L4"><code class="lang-html"><span class="pln">    </span><span class="tag">&lt;/script&gt;</span></code></li><li class="L5"><code class="lang-html"><span class="tag">&lt;/body&gt;</span></code></li><li class="L6"><code class="lang-html"><span class="tag">&lt;/html&gt;</span></code></li></ol></pre>
