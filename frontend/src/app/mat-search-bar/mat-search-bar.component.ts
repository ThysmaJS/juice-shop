import {
  animate,
  state,
  style,
  transition,
  trigger
} from '@angular/animations'
import {
  Component,
  ElementRef,
  EventEmitter,
  forwardRef,
  Input,
  type OnInit,
  Output,
  ViewChild
} from '@angular/core'
import { FormControl, NG_VALUE_ACCESSOR, FormsModule } from '@angular/forms'
import { MatAutocomplete } from '@angular/material/autocomplete'
import { AbstractControlValueAccessor } from './abstract-value-accessor'
import { MatRipple } from '@angular/material/core'
import { MatIconModule } from '@angular/material/icon'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule } from '@angular/material/form-field'

@Component({
  selector: 'app-mat-search-bar',
  templateUrl: './mat-search-bar.component.html',
  styleUrls: ['./mat-search-bar.component.scss'],
  animations: [
    trigger('slideInOut', [
      state('true', style({ width: '*' })),
      state('false', style({ width: '0' })),
      transition('true => false', animate('300ms ease-in')),
      transition('false => true', animate('300ms ease-out'))
    ])
  ],
  providers: [
    {
      provide: NG_VALUE_ACCESSOR,
      useExisting: forwardRef(() => MatSearchBarComponent),
      multi: true
    }
  ],
  imports: [MatFormFieldModule, MatInputModule, FormsModule, MatIconModule, MatRipple]
})
export class MatSearchBarComponent extends AbstractControlValueAccessor
  implements OnInit {
  @ViewChild('input') inputElement: ElementRef

  @Input() formControl: FormControl
  @Input() matAutocomplete: MatAutocomplete
  @Input() placeholder = ''
  @Input() alwaysOpen = false
  // Angular outputs should not be prefixed with "on"
  @Output() blur = new EventEmitter<string>()
  @Output() closed = new EventEmitter<void>()
  @Output() enter = new EventEmitter<string>()
  @Output() focus = new EventEmitter<string>()
  @Output() opened = new EventEmitter<void>()

  searchVisible = false

  get isDisabled (): string {
    return this.searchVisible ? null : 'disabled'
  }

  ngOnInit (): void {
    if (this.alwaysOpen) {
      this.searchVisible = true
    }
  }

  public close (): void {
    if (!this.alwaysOpen) {
      this.searchVisible = false
    }
    this.value = ''
    this.updateChanges()
    this.closed.emit()
  }

  public open (): void {
    this.searchVisible = true
    this.inputElement.nativeElement.focus()
    this.opened.emit()
  }

  onBlurring (searchValue: string) {
    if (!searchValue && !this.alwaysOpen) {
      this.searchVisible = false
    }
    this.blur.emit(searchValue)
  }

  onEnterring (searchValue: string) {
    this.enter.emit(searchValue)
  }

  onFocussing (searchValue: string) {
    this.focus.emit(searchValue)
  }
}
