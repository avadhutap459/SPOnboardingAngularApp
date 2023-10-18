using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Ver1._0_QuestaEnneagram.APILayer.JWT_Token_Auth.Model;

namespace Ver1._0_QuestaEnneagram.APILayer.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CandidateController : ControllerBase
    {
        private IMaster MasterCls { get; set; }
        private IConfiguration _configuration { get; set; }
        private ICandidate CandidateCls { get; set; }
        private IMail MailCls { get; set; }
        public CandidateController(IMaster MasterCls, IConfiguration configuration, ICandidate CandidateCls, IMail MailCls)
        {
            this.MasterCls = MasterCls;
            this._configuration = configuration;
            this.CandidateCls = CandidateCls;
            this.MailCls = MailCls;
        }
        [HttpGet]
        //  [CustomAuthorizeAttribute]
        [Route("GetuserClaim")]
        public IActionResult GetuserClaim()
        {
            try
            {
                var identity = (ClaimsIdentity)User.Identity;
                if (identity != null)
                {

                    Claim claim = identity?.FindFirst(ClaimTypes.Name);


                    int TestId = claim == null ? 0 : int.Parse(claim.Value);

                    CandidateBM CandidateData = CandidateCls.GetCandidateDetailsByTestId(TestId);

                    string emailId = CandidateData.Email;
                    string Name = CandidateData.FirstName;

                    int CurrentSetId = CandidateCls.GetLatestSetIdBaseOnTestId(CandidateData.TestId);

                    var UserDetail = new
                    {
                        Username = emailId,
                        TestId = CandidateData.TestId,
                        SetId = CurrentSetId,
                        Name = Name
                    };
                    return Ok(new { userAuth = UserDetail });
                }
                else
                {
                    return NotFound();
                }

                // return Ok(identity);
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        [HttpGet]
        [Route("GetCandiateDetails/{TestId}")]
        public IActionResult GetCandiateDetails(int TestId)
        {
            try
            {
                bool IsDisableAllControl = false;

                #region GetMasterDetails

                MasterBM MasterData = MasterCls.GetMasterData().Result;

                #endregion

                #region Get Candidate Details
                CandidateBM CandidateData = CandidateCls.GetCandidateDetailsByTestId(TestId);
                
                if (CandidateData == null)
                {
                    return NotFound(new { IsSuccess = false, message = "User does not exit in current database" });
                }
                CandidateData.Industry = CandidateCls.GetIndustryByTestId(TestId);
                IsDisableAllControl = CandidateData.GenderId != null ? true : false;
                #endregion

                return Ok(new { IsSuccess = true, MasterObject = MasterData, CandidateObject = CandidateData, IsDisableAllControl = IsDisableAllControl });
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                this.MasterCls.Dispose();

                this.CandidateCls.Dispose();
            }
        }

        [HttpGet]
        [Route("GetState/{CountryId}")]
        public async Task<IActionResult> GetState(int CountryId)
        {
            try
            {
                List<StateBM> StateList = MasterCls.GetStateDetailsByCountryId(CountryId).Result;

                return Ok(new { StateObject = StateList });
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                this.MasterCls.Dispose();
            }
        }


        [HttpPost]
        [Route("SaveCandidateDetails")]
        public IActionResult SaveCandidateDetails(CandidateBM CandidateModel)
        {
            try
            {
                CandidateModel.DateOfBirth = CandidateModel.DateOfBirth == null ? (DateTime?)null : CandidateModel.DateOfBirth.Value.AddDays(1);

                if (CandidateModel.IsActive)
                {
                    if (CandidateCls.IsDateDifferenceForOneYear(CandidateModel.CandidateId.Value))
                    {
                        return Ok(new
                        {
                            message = "Please Note : The link you clicked on has expired,as ie was valid for a duration of 15 days from the date of payment Please contact us at support@questaenneagram.com for further assistance. ",
                            isSuccess = false
                        });
                    }
                    else
                    {
                        var CandidateData = CandidateCls.SaveCandidateDetails(CandidateModel).Result;
                        bool IsSucess = CandidateData.Item2;
                        string Message = CandidateData.Item1;
                        if (IsSucess && string.IsNullOrEmpty(Message))
                        {
                            var Token = CreateToken(CandidateModel.TestId);

                            var _refreshToken = GenerateRefreshToken();

                            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInMinutes"], out int refreshTokenValidityInMin);

                            string InsertQuery = "INSERT INTO [dbo].[TxnRefreshToken](TestId,RefreshToken,RefreshTokenCreatedTime,RefreshTokenExpiryTime)" +
                                    "Values(@TestId,@RefreshToken,@RefreshTokenCreatedTime,@RefreshTokenExpiryTime)";
                            
                            var parameters = new
                            {
                                TestId = CandidateModel.TestId,
                                RefreshToken = _refreshToken,
                                RefreshTokenCreatedTime = DateTime.Now,
                                RefreshTokenExpiryTime = DateTime.Now.AddMinutes(refreshTokenValidityInMin)
                            };

                            CandidateCls.InsertUpdateDeleteForCandidate<Object>(parameters, InsertQuery);

                            var _Token = new JwtSecurityTokenHandler().WriteToken(Token);

                            SetRefreshToken(_refreshToken);

                            return Ok(new { ExamId = CandidateModel.TestId, isSuccess = true, Token = _Token, RefreshToken = _refreshToken });
                        }
                        else
                        {
                            return Unauthorized(new { message = Message, isSuccess = false });
                        }
                    }
                }
                else
                {
                    return NotFound(new { message = "Particular candidate does not active ", IsSuccess = false });
                }
            }
            catch(Exception ex)
            {
                throw;
            }
            finally
            {
                this.CandidateCls.Dispose();
            }
        }

        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenModel tokenModel)
        {
            if (tokenModel is null)
            {
                return BadRequest("Invalid client request");
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);

            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }
            string _TestId = principal.Identity.Name;
            _ = int.TryParse(_TestId, out int TestId);

            var RefreshTokenModel = CandidateCls.GetRefreshTokenByTestId(TestId);

            if (RefreshTokenModel == null || RefreshTokenModel.RefreshToken != refreshToken || RefreshTokenModel.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            _ = int.TryParse(_configuration["JWT:RefreshTokenValidityInMinutes"], out int refreshTokenValidityInMinutes);

            var newAccessToken = CreateToken(TestId);
            var newRefreshToken = GenerateRefreshToken();

            string UpdateQuery = "UPDATE [dbo].[TxnRefreshToken] SET RefreshToken = @RefreshToken," +
                                    "RefreshTokenCreatedTime=@RefreshTokenCreatedTime,RefreshTokenExpiryTime=@RefreshTokenExpiryTime " +
                                 "WHERE TestId=@TestId and RefreshTokenId = @RefreshTokenId ";

            var parameters = new
            {
                RefreshTokenId = RefreshTokenModel.RefreshTokenId,
                TestId = TestId,
                RefreshToken = newRefreshToken,
                RefreshTokenCreatedTime = DateTime.Now,
                RefreshTokenExpiryTime = DateTime.Now.AddMinutes(refreshTokenValidityInMinutes)
            };

            CandidateCls.InsertUpdateDeleteForCandidate<Object>(parameters, UpdateQuery);

            var _Token = new JwtSecurityTokenHandler().WriteToken(newAccessToken);

            return Ok(new { ExamId = TestId, isSuccess = true, Token = _Token, RefreshToken = newRefreshToken });
        }

        [HttpGet]
        [Route("AssessmentLink/{CompanyId}/{AssessmentId}/{HrId}/{LinkCount}/{InitialMailId}/{FinalMailId}/{LinkSent}/{ReportToSent}/{IsBulkSentRequire}")]
        public IActionResult GenerateAssessmentLink(int CompanyId,int AssessmentId,int HrId,int LinkCount,int InitialMailId,int FinalMailId,EnumLinkToSent LinkSent, EnumReportToSent ReportToSent,bool IsBulkSentRequire )
        {
            try
            {
                if (!MasterCls.IsValidCompany(CompanyId))
                {
                    var response = new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        Content = new StringContent("Please provide valid company Id or contact to developer", System.Text.Encoding.UTF8, "text/plain"),
                        StatusCode = HttpStatusCode.NotFound
                    };
                    return BadRequest(response);
                }

                if (!MasterCls.IsValidHrId(HrId))
                {
                    var response = new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        Content = new StringContent("Please provide valid hr Id or contact to developer", System.Text.Encoding.UTF8, "text/plain"),
                        StatusCode = HttpStatusCode.NotFound
                    };
                    return BadRequest(response);
                }

                if (!MasterCls.IsValidAssessmentId(AssessmentId))
                {
                    var response = new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        Content = new StringContent("Please provide valid Assessment Id or contact to developer", System.Text.Encoding.UTF8, "text/plain"),
                        StatusCode = HttpStatusCode.NotFound
                    };
                    return BadRequest(response);
                }

                if (!MasterCls.IsValidMailId(InitialMailId))
                {
                    var response = new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        Content = new StringContent("Please provide valid initial mail Id or contact to developer", System.Text.Encoding.UTF8, "text/plain"),
                        StatusCode = HttpStatusCode.NotFound
                    };
                    return BadRequest(response);
                }

                if (!MasterCls.IsValidMailId(FinalMailId))
                {
                    var response = new HttpResponseMessage(HttpStatusCode.NotFound)
                    {
                        Content = new StringContent("Please provide valid final mail Id or contact to developer", System.Text.Encoding.UTF8, "text/plain"),
                        StatusCode = HttpStatusCode.NotFound
                    };
                    return BadRequest(response);
                }

                string DnsUrl = _configuration.GetValue<string>("APIUrl");

                MailBM ObjMail = MailCls.GetSenderUserDetails(HrId, true, InitialMailId);
                string GenerateUrl = string.Empty;

                if (IsBulkSentRequire)
                {
                    for (int i = 0; i <= LinkCount - 1; i++)
                    {
                        //int TestId = CandidateCls.GenerateTestId(AssessmentId, null, null, null, CompanyId, HrId, (int)LinkSent, (int)ReportToSent).Value;
                        
                        int TestId = CandidateCls.GenerateLinkForCanidate(AssessmentId, CompanyId, HrId, (int)LinkSent, (int)ReportToSent).Value;

                        string URL = DnsUrl + TestId;

                        var CandidateDetails = CandidateCls.GetCandidateDetailsByTestId(TestId);

                        MailCls.SaveMailTemplateToCandidate(CandidateDetails.CandidateId.Value, InitialMailId, FinalMailId);

                        GenerateUrl = GenerateUrl + "<a href=" + URL + " target='_self'>" + URL + "</a> <br/>";
                    }
                }
                else
                {
                    //  int TestId = CandidateCls.GenerateTestId(AssessmentId, null, null, null, CompanyId, HrId, (int)LinkSent, (int)ReportToSent).Value;
                    int TestId = CandidateCls.GenerateLinkForCanidate(AssessmentId, CompanyId, HrId, (int)LinkSent, (int)ReportToSent).Value;

                    string URL = DnsUrl + TestId;
                    var CandidateDetails = CandidateCls.GetCandidateDetailsByTestId(TestId);

                    MailCls.SaveMailTemplateToCandidate(CandidateDetails.CandidateId.Value, InitialMailId, FinalMailId);

                    GenerateUrl = GenerateUrl + "<a href=" + URL + " target='_self'>" + URL + "</a>";
                }
                Task.Run(async () => await this.MailCls.InitialMailSent(ObjMail, GenerateUrl));
                return Ok(new { URL = GenerateUrl, isSuccess = true });
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                MasterCls.Dispose();
                MailCls.Dispose();
                CandidateCls.Dispose();
            }
        }

        [HttpGet]
        [Route("UpdateIsLogin/{IsLogin}/{TestId}")]
        public IActionResult UpdateIsLogin(bool IsLogin, int TestId)
        {
            try
            {
                CandidateCls.UpdateIdLogin(TestId, IsLogin);

                return Ok(new { isSuccess = true });

            }
            catch (Exception ex)
            {
                throw new NotImplementedException(ex.Message);
                //return BadRequest(ex.Message.ToString());
            }
            finally
            {
                this.CandidateCls.Dispose();
            }
        }
        #region Token Generation Logic
        private JwtSecurityToken CreateToken(int TestId)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, TestId.ToString()),
                new Claim(ClaimTypes.Role, "Candidate")
            };

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: claims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private void SetRefreshToken(string RefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(30)
            };
            Response.Cookies.Append("refreshToken", RefreshToken, cookieOptions);

        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken();
            // if (securityToken != jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            //    throw new SecurityTokenException("Invalid token");

            return principal;

        }
        #endregion


    }
}
