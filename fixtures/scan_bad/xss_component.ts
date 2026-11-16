// Angular component: sanitizer bypasses mark runtime data as safe HTML.
// User-influenced values passed to bypassSecurityTrust* / the Angular >= 15
// bypassSanitizationTrust* rename skip the built-in XSS sanitizer.
import { Component, input } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-bio',
  template: '<div [innerHTML]="trustedBio"></div>',
})
export class BioComponent {
  trustedBio = this.sanitizer.bypassSecurityTrustHtml(this.inlineBio());
  videoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(this.clipUrl());
  footer = this.sanitizer.bypassSecurityTrustHtml('<p class="muted">built by app</p>');
  style = this.sanitizer.bypassSanitizationTrustStyle(this.theme.colors);
}
