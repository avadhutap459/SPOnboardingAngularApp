import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { BehaviorSubject, Observable } from "rxjs";
import { map } from "rxjs/operators";
import { environment } from "src/environments/environment";
import { CandidateBusinessModel, CandidateToken } from "../_model/candidate-business-model.model";

@Injectable({
    providedIn: 'root'
})
export class AuthenticationService {

    private userSubject: BehaviorSubject<any>;
     _token: CandidateToken = new CandidateToken();
    ApiUrl =environment.apiEndpoint;

    constructor(private _http: HttpClient) {

        this.userSubject = new BehaviorSubject<CandidateToken | null>(null);
    }
    public get CurrentTokenValue(): any {
        return this.userSubject.value;
    }

    public setCurrentTokenValue(tokenValue: any) {
        this.userSubject.next(tokenValue);
    }

    SetCurrentTokenValueNull() {
        this.userSubject.next(null);
    }

    login(User: CandidateBusinessModel): Observable<any> {
        const headers = new HttpHeaders().set('content-type', 'application/json');
        var body = {
            CandidateId: User.CandidateId,
            TestId: User.TestId,
            Title: User.Title,
            FirstName: User.FirstName,
            MiddenName : User.MiddenName,
            LastName: User.LastName,
            Email: User.Email,
            PhoneNumber: User.PhoneNumber,
            GenderId: User.GenderId,
            AgeId: User.AgeId,
            StateId: User.StateId,
            CountryId: User.CountryId,
            QualificationId: User.QualificationId,
            ProfessionalId: User.ProfessionalId,
            GenderTxt: User.GenderTxt,
            MaritalStatusId: User.MaritalStatusId,
            Industry: User.Industry,
            QualificationTxt: User.QualificationTxt,
            EmployeeStatusId: User.EmployeeStatusId,
            IsConnectedViaMobile: User.IsConnectedViaMobile,
            IsConnectedViaDesktop: User.IsConnectedViaDesktop,
            IsConnectedViaTab: User.IsConnectedViaTab,
            BrowserName: User.BrowserName,
            DateOfBirth: User.DateOfBirth,
            ExperienceId: User.ExperienceId,
            IsLogin : User.IsLogin,
            IsActive : User.IsActive
        }
        let options = {
            headers: headers
        }
        return this._http.post<any>(this.ApiUrl + '/api/Candidate/SaveCandidateDetails', body, options).pipe(map(user => {
            this._token.RefreshToken = user.RefreshToken;
            this._token.Token = user.Token;
            this.userSubject.next(this._token);
            localStorage.setItem('userToken', user.Token);
            localStorage.setItem('RefreshToken', user.RefreshToken);
            this.startRefreshTokenTimer();
            return user;
        }));
    }

    public get userValue(): any {
        return this.userSubject.value;
    }
    private refreshTokenTimeout;

    private startRefreshTokenTimer() {

        //  this.decodedToken = decodeToken(this.userValue.Token);
        // console.log(isTokenValid(this.decodedToken.exp));
        const jwtToken = JSON.parse(atob(this.userValue.Token.split('.')[1]));
        // set a timeout to refresh the token a minute before it expires
        const expires = new Date(jwtToken.exp * 1000);
        const timeout = Date.now() - expires.getTime() - (60 * 1000);
        this.refreshTokenTimeout = setTimeout(() => this.refreshToken().subscribe(), 1800000);
    }

    refreshToken() {
        const headers = new HttpHeaders().set('content-type', 'application/json');
        var body = {
            AccessToken: this.userValue.Token,
            RefreshToken: this.userValue.RefreshToken
        }
        let options = {
            headers: headers
        }

        return this._http.post<any>(this.ApiUrl +  '/api/Candidate/refresh-token', body, options)
            .pipe(map((user) => {
                this._token.RefreshToken = user.RefreshToken;
                this._token.Token = user.Token;
                this.userSubject.next(this._token);
                localStorage.setItem('userToken', user.accessToken);
                localStorage.setItem('RefreshToken', user.Token);
                this.startRefreshTokenTimer();
                return user;
            }));

    }

    private stopRefreshTokenTimer() {
        clearTimeout(this.refreshTokenTimeout);
    }

}