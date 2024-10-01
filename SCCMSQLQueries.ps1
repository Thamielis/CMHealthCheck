
$v_CH_ClientHealth = @"
    Select 
            * 
    from 
            v_CH_ClientHealth 
    where 
            LastOnlineTime is not null and 
            LastActiveTime is not null
"@

$v_CH_ClientSummary = @"
    Select 
            * 
    from 
            v_CH_ClientSummary
"@

$FailedUnknownClientHealth = @"
Select 
    sys.Name0 as 'ComputerName',
    sys.User_Name0 as 'UserName',
    cs.ClientStateDescription,
    DATEDIFF(day,sys.Creation_Date0,cs.LastActiveTime) as 'Days Active',
    DATEDIFF(day,cs.LastHealthEvaluation,GetDate()) as 'Days Since Last Eval',
    sys.Creation_Date0 as 'SCCM Client Registration Date',
    cs.LastActiveTime, 
    cs.LastHealthEvaluation,
    case 
        when LastEvaluationHealthy = 1 then 'Pass'
        when LastEvaluationHealthy = 2 then 'Fail'
        when LastEvaluationHealthy = 3 then 'Unknown'
    end as 'Last Evaluation Healthy',
    case 
        when cs.ClientRemediationSuccess = 1 then 'Pass'
        when cs.ClientRemediationSuccess = 2 then 'Fail'
        else ''
    end as 'ClientRemediationSuccess',
    case 
        when LastHealthEvaluationResult = 1 then 'Not Yet Evaluated'
        when LastHealthEvaluationResult = 2 then 'Not Applicable'
        when LastHealthEvaluationResult = 3 then 'Evaluation Failed'
        when LastHealthEvaluationResult = 4 then 'Evaluated Remediated Failed'
        when LastHealthEvaluationResult = 5 then 'Not Evaluated Dependency Failed'
        when LastHealthEvaluationResult = 6 then 'Evaluated Remediated Succeeded'
        when LastHealthEvaluationResult = 7 then 'Evaluation Succeeded'
    end as 'LastHealthEvaluationResult',
    HealthCheckDescription,
    ResultDetail,
    ResultCode
from 
    dbo.v_CH_ClientSummary cs
    inner join v_R_System sys on cs.ResourceID = sys.ResourceID
    left join v_CH_EvalResults eval on cs.ResourceID = eval.ResourceID
where 
    cs.ClientStateDescription in ('Active/Fail','Active/Unknown')
    and DATEDIFF(day,sys.Creation_Date0,cs.LastActiveTime) > 7
Order by 
    ClientStateDescription,
    ComputerName
"@

$ServiceUsers = @"
Select
    Sys.Name0,
    Sys.Description0,
    Svc.DisplayName0,
    Svc.Name0,
    Svc.StartName0,
    Svc.StartMode0,
    Sys.User_Name0
from
    v_GS_SERVICE As Svc
    INNER JOIN v_R_System As Sys 
        ON Svc.ResourceID = Sys.ResourceID
where
    Sys.Operating_System_Name_and0 like '%Server%' AND
    (Svc.StartName0 like 'SERVER%' OR Svc.StartName0 like 'kostwein%')
    --Svc.StartName00 like '%\%' --'SERVER%'
ORDER BY
    Svc.StartName0
"@
