import { forwardRef, type ChangeEvent } from 'react'
import styles from './SearchInput.module.css'

interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}

const SearchInput = forwardRef<HTMLInputElement, SearchInputProps>(function SearchInput(
  { value, onChange, placeholder },
  ref,
) {
  function handleChange(event: ChangeEvent<HTMLInputElement>) {
    onChange(event.target.value)
  }

  return (
    <div className={styles.wrap}>
      <svg
        className={styles.icon}
        width="15"
        height="15"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="2" />
        <path d="M21 21l-4.3-4.3" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
      <input
        ref={ref}
        className={styles.input}
        type="search"
        value={value}
        onChange={handleChange}
        placeholder={placeholder ?? 'Search scenarios, MITRE / ATRM IDs…'}
        aria-label="Search threat scenarios"
      />
      {!value && (
        <kbd className={styles.hint} aria-hidden="true">
          /
        </kbd>
      )}
    </div>
  )
})

export default SearchInput
