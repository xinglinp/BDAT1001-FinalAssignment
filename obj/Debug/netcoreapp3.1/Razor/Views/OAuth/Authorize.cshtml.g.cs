#pragma checksum "D:\1001 final pj\Authentication\Server\Views\OAuth\Authorize.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "0d6118afa22df8959adeff0a588865e7d5f5025c"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_OAuth_Authorize), @"mvc.1.0.view", @"/Views/OAuth/Authorize.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"0d6118afa22df8959adeff0a588865e7d5f5025c", @"/Views/OAuth/Authorize.cshtml")]
    public class Views_OAuth_Authorize : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<string>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
#nullable restore
#line 3 "D:\1001 final pj\Authentication\Server\Views\OAuth\Authorize.cshtml"
  
    var url = $"/OAuth/Authorize{Model}";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n\r\n");
#nullable restore
#line 8 "D:\1001 final pj\Authentication\Server\Views\OAuth\Authorize.cshtml"
Write(Model);

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n\r\n<from");
            BeginWriteAttribute("action", " action=\"", 86, "\"", 99, 1);
#nullable restore
#line 10 "D:\1001 final pj\Authentication\Server\Views\OAuth\Authorize.cshtml"
WriteAttributeValue("", 95, url, 95, 4, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(" method=\"post\">\r\n    <input type=\"text\" name=\"username\"");
            BeginWriteAttribute("value", " value=\"", 155, "\"", 163, 0);
            EndWriteAttribute();
            WriteLiteral(" />\r\n    <input type=\"submit\"  value=\"submit\" />\r\n</from>");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<string> Html { get; private set; }
    }
}
#pragma warning restore 1591
