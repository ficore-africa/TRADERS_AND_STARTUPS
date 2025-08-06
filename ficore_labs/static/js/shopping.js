document.addEventListener('DOMContentLoaded', function() {
    // Translation map for help text and UI messages
    const helpTextTranslations = {
        'budget': "Enter your budget (e.g., 100,000 or 100,000.00)",
        'quantity': "Enter the number of units (e.g., 2 cartons, 5 pieces)",
        'price': "Enter price per unit (e.g., price for one carton or piece)",
        'frequency': "Enter frequency in days (e.g., 7)",
        'amount_max': "Input cannot exceed 10 billion",
        'amount_positive': "Amount must be positive",
        'quantity_max': "Quantity cannot exceed 1000",
        'frequency_max': "Frequency cannot exceed 365 days",
        'budget_required': "Budget is required",
        'name_required': "Please enter a valid list name",
        'item_added': "Item added successfully!",
        'add_item_error': "Failed to add item. Please try again.",
        'edit_item_error': "Failed to save item changes. Please try again.",
        'delete_item_error': "Failed to delete item. Please try again.",
        'table_error': "Failed to load items. Please try again.",
        'duplicate_item_name': "Item name already exists in this list.",
        'csrf_error': "Form submission failed due to a missing security token. Please refresh and try again."
    };

    // Helper function to show toasts
    function showToast(message, type = 'danger') {
        const toastContainer = document.querySelector('.toast-container');
        if (!toastContainer) {
            console.warn('Toast container not found.');
            return;
        }
        const toastEl = document.createElement('div');
        toastEl.className = `toast align-items-center text-white bg-${type} border-0`;
        toastEl.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
        `;
        toastContainer.appendChild(toastEl);
        new bootstrap.Toast(toastEl).show();
    }

    // Helper function to format a number for display
    function formatForDisplay(value, isInteger) {
        if (value === null || value === undefined || isNaN(value)) {
            return isInteger ? '0' : '0.00';
        }
        return isInteger
            ? parseInt(value).toLocaleString('en-US', { maximumFractionDigits: 0 })
            : parseFloat(value).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    // Helper function to clean input for numeric parsing
    function cleanForParse(value) {
        if (!value && value !== 0) return '';
        // Remove all non-numeric characters except one decimal point
        let clean = value.toString().replace(/[^0-9.]/g, '');
        const parts = clean.split('.');
        if (parts.length > 2) {
            clean = parts[0] + '.' + parts[1].slice(0, 2); // Keep only first decimal point and up to 2 decimal places
        } else if (parts.length === 2) {
            clean = parts[0] + (parts[1] ? '.' + parts[1].slice(0, 2) : '');
        }
        return clean;
    }

    // Apply formatting and validation to number inputs
    function initializeNumberInputs() {
        document.querySelectorAll('.number-input').forEach(input => {
            const isInteger = input.id.includes('quantity') || input.id.includes('frequency') || input.classList.contains('new-item-quantity') || input.classList.contains('new-item-frequency');
            const allowCommas = input.dataset.allowCommas === 'true';
            const originalHelpText = helpTextTranslations[input.id.replace('edit-item-', '').replace('item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['quantity'] || helpTextTranslations['price'] || helpTextTranslations['frequency'];

            // Initialize value on load
            if (input.value) {
                let rawValue = cleanForParse(input.value);
                let numValue = isInteger ? parseInt(rawValue) : parseFloat(rawValue);
                if (!isNaN(numValue) && numValue >= 0) {
                    input.value = isInteger ? numValue.toString() : formatForDisplay(numValue, false);
                } else {
                    input.value = '';
                }
            }

            input.addEventListener('focus', function() {
                if (allowCommas && input.value) {
                    input.value = cleanForParse(input.value);
                }
            });

            input.addEventListener('blur', function() {
                let rawValue = cleanForParse(input.value);
                let numValue = isInteger ? parseInt(rawValue) || 0 : parseFloat(rawValue) || 0;
                const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling.nextElementSibling : input.nextElementSibling;

                if (isInteger) {
                    if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) {
                        numValue = 1000;
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['quantity_max'];
                    } else if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) {
                        numValue = 365;
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['frequency_max'];
                    } else if (numValue <= 0 && input.hasAttribute('required')) {
                        numValue = 0;
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                    } else {
                        input.classList.remove('is-invalid');
                        if (helpElement) helpElement.innerText = originalHelpText;
                    }
                    input.value = numValue.toString();
                } else {
                    if (!rawValue && input.hasAttribute('required')) {
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                    } else if (isNaN(numValue) && input.hasAttribute('required')) {
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                    } else if (numValue > 10000000000) {
                        numValue = 10000000000;
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['amount_max'];
                    } else if (numValue <= 0 && input.hasAttribute('required')) {
                        numValue = 0;
                        input.classList.add('is-invalid');
                        if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                    } else {
                        input.classList.remove('is-invalid');
                        if (helpElement) helpElement.innerText = originalHelpText;
                    }
                    input.value = allowCommas && !isNaN(numValue) ? formatForDisplay(numValue, false) : (isNaN(numValue) ? '' : numValue.toFixed(2));
                }
                updateBudgetProgress(input.closest('form'));
            });

            input.addEventListener('input', function() {
                let value = input.value;
                let cleanedValue = isInteger ? value.replace(/[^0-9]/g, '') : value.replace(/[^0-9.]/g, '');
                if (!isInteger && allowCommas) {
                    const parts = cleanedValue.split('.');
                    if (parts.length > 2) {
                        cleanedValue = parts[0] + '.' + parts[1];
                    }
                }
                if (input.value !== cleanedValue) {
                    const start = input.selectionStart;
                    const end = input.selectionEnd;
                    input.value = cleanedValue;
                    input.setSelectionRange(start, end);
                }
                input.classList.remove('is-invalid');
                updateBudgetProgress(input.closest('form'));
            });

            input.addEventListener('paste', function(e) {
                e.preventDefault();
                let pasted = (e.clipboardData || window.clipboardData).getData('text');
                let clean = cleanForParse(pasted);
                if (!clean) return;

                let numValue = isInteger ? parseInt(clean) || 0 : parseFloat(clean) || 0;
                if (isInteger) {
                    if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) numValue = 1000;
                    if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) numValue = 365;
                    input.value = numValue.toString();
                } else {
                    input.value = allowCommas && !isNaN(numValue) ? formatForDisplay(numValue, false) : numValue.toFixed(2);
                }
                input.dispatchEvent(new Event('blur'));
                updateBudgetProgress(input.closest('form'));
            });

            // Trigger blur on load to format initial value
            if (input.value) {
                input.dispatchEvent(new Event('blur'));
            }
        });
    }

    // Form validation on submit
    function initializeFormValidation() {
        document.querySelectorAll('.validate-form').forEach(form => {
            if (!form) return;
            form.addEventListener('submit', function(e) {
                if (window.isAuthenticatedContentBlocked) {
                    e.preventDefault();
                    showToast('Please log in to perform this action.', 'danger');
                    return;
                }
                let formIsValid = true;

                // Debug: Log form submission attempt
                console.log('Form submission attempted:', form.id, 'Values:', {
                    name: form.querySelector('#list_name')?.value,
                    budget: form.querySelector('#list_budget')?.value
                });

                // Clean budget field before submission
                const budgetInput = form.querySelector('#list_budget');
                if (budgetInput) {
                    const rawBudget = budgetInput.value;
                    const cleanedBudget = cleanForParse(rawBudget);
                    budgetInput.value = cleanedBudget;
                    console.log('Budget cleaned:', { raw: rawBudget, cleaned: cleanedBudget });
                }

                // Validate required fields
                form.querySelectorAll('[required]').forEach(input => {
                    if (!input.value.trim()) {
                        input.classList.add('is-invalid');
                        const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling : input.nextElementSibling?.nextElementSibling;
                        if (helpElement) {
                            helpElement.innerText = input.id.includes('name')
                                ? helpTextTranslations['name_required']
                                : helpTextTranslations['budget_required'];
                        }
                        formIsValid = false;
                        console.log('Validation failed for required field:', input.id);
                    } else {
                        input.classList.remove('is-invalid');
                        const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling.nextElementSibling : input.nextElementSibling;
                        if (helpElement) {
                            helpElement.innerText = helpTextTranslations[input.id.replace('edit-item-', '').replace('item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['name'];
                        }
                    }
                });

                // Validate number inputs
                form.querySelectorAll('.number-input').forEach(input => {
                    const isInteger = input.id.includes('quantity') || input.id.includes('frequency') || input.classList.contains('new-item-quantity') || input.classList.contains('new-item-frequency');
                    const allowCommas = input.dataset.allowCommas === 'true';
                    let rawValue = cleanForParse(input.value);
                    let numValue = isInteger ? parseInt(rawValue) || 0 : parseFloat(rawValue) || 0;
                    const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling.nextElementSibling : input.nextElementSibling;

                    if (isInteger) {
                        if ((input.id.includes('quantity') || input.classList.contains('new-item-quantity')) && numValue > 1000) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['quantity_max'];
                            formIsValid = false;
                        } else if ((input.id.includes('frequency') || input.classList.contains('new-item-frequency')) && numValue > 365) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['frequency_max'];
                            formIsValid = false;
                        } else if (numValue <= 0 && input.hasAttribute('required')) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                            formIsValid = false;
                        } else {
                            input.classList.remove('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations[input.id.replace('edit-item-', '').replace('item-', '')] || helpTextTranslations['quantity'] || helpTextTranslations['frequency'];
                        }
                        input.value = numValue.toString();
                    } else {
                        if (!rawValue && input.hasAttribute('required')) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                            formIsValid = false;
                            console.log('Budget validation failed: empty or invalid', { rawValue, numValue });
                        } else if (isNaN(numValue) && input.hasAttribute('required')) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                            formIsValid = false;
                            console.log('Budget validation failed: NaN', { rawValue, numValue });
                        } else if (numValue > 10000000000) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['amount_max'];
                            formIsValid = false;
                            console.log('Budget validation failed: exceeds max', { rawValue, numValue });
                        } else if (numValue <= 0 && input.hasAttribute('required')) {
                            input.classList.add('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                            formIsValid = false;
                            console.log('Budget validation failed: non-positive', { rawValue, numValue });
                        } else {
                            input.classList.remove('is-invalid');
                            if (helpElement) helpElement.innerText = helpTextTranslations[input.id.replace('edit-item-', '').replace('item-', '')] || helpTextTranslations['budget'] || helpTextTranslations['price'];
                        }
                        input.value = allowCommas && !isNaN(numValue) ? formatForDisplay(numValue, false) : (isNaN(numValue) ? '' : numValue.toFixed(2));
                    }
                });

                if (!formIsValid && !form.dataset.allowSubmit) {
                    e.preventDefault();
                    const firstInvalid = form.querySelector('.is-invalid');
                    if (firstInvalid) {
                        firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        firstInvalid.focus();
                    }
                    console.log('Form submission blocked due to validation errors');
                    return;
                }

                const submitButton = form.querySelector('button[type="submit"]');
                if (submitButton && formIsValid) {
                    submitButton.disabled = true;
                    const spinner = submitButton.querySelector('.spinner-border');
                    if (spinner) spinner.classList.remove('d-none');
                    const icon = submitButton.querySelector('i');
                    if (icon) icon.classList.add('d-none');
                    console.log('Form submission proceeding:', form.id);
                }
            });
        });
    }

    // Open edit modal
    window.openEditModal = function(id, name, quantity, price, unit, category, status, store, frequency) {
        try {
            const idInput = document.getElementById('edit-item-id');
            if (!idInput) throw new Error('Edit item ID input not found');
            idInput.value = id;

            const nameInput = document.getElementById('edit-item-name');
            if (nameInput) nameInput.value = name;

            const quantityInput = document.getElementById('edit-item-quantity');
            if (quantityInput) quantityInput.value = quantity;

            const priceInput = document.getElementById('edit-item-price');
            if (priceInput) priceInput.value = formatForDisplay(price, false);

            const unitSelect = document.getElementById('edit-item-unit');
            if (unitSelect) unitSelect.value = unit;

            const categorySelect = document.getElementById('edit-item-category');
            if (categorySelect) categorySelect.value = category;

            const statusSelect = document.getElementById('edit-item-status');
            if (statusSelect) statusSelect.value = status;

            const storeInput = document.getElementById('edit-item-store');
            if (storeInput) storeInput.value = store;

            const frequencyInput = document.getElementById('edit-item-frequency');
            if (frequencyInput) frequencyInput.value = frequency;

            const modal = new bootstrap.Modal(document.getElementById('editItemModal'));
            modal.show();
        } catch (error) {
            console.error('Error opening edit modal:', error);
            showToast("Failed to open edit modal. Please try again.", 'danger');
        }
    };

    // Save edited item
    document.getElementById('saveEditItem')?.addEventListener('click', function() {
        const form = document.getElementById('addItemsForm') || document.getElementById('addItemForm');
        if (!form) {
            console.error('Form not found for saving edited item');
            showToast("Form not found. Please try again.", 'danger');
            return;
        }

        try {
            const id = document.getElementById('edit-item-id')?.value;
            if (!id) throw new Error('Item ID not found');

            const newItem = {
                id: id,
                name: document.getElementById('edit-item-name')?.value.trim() || '',
                quantity: parseInt(document.getElementById('edit-item-quantity')?.value) || 1,
                price: parseFloat(cleanForParse(document.getElementById('edit-item-price')?.value)) || 0,
                unit: document.getElementById('edit-item-unit')?.value || 'unit',
                category: document.getElementById('edit-item-category')?.value || 'general',
                status: document.getElementById('edit-item-status')?.value || 'pending',
                store: document.getElementById('edit-item-store')?.value.trim() || '',
                frequency: parseInt(document.getElementById('edit-item-frequency')?.value) || 1
            };

            if (!newItem.name.trim()) {
                const nameInput = document.getElementById('edit-item-name');
                if (nameInput) {
                    nameInput.classList.add('is-invalid');
                    const helpElement = nameInput.nextElementSibling;
                    if (helpElement) helpElement.innerText = helpTextTranslations['name_required'];
                }
                return;
            }

            const csrfToken = form.querySelector('input[name="csrf_token"]')?.value || window.CSRF_TOKEN || '';
            if (!csrfToken) {
                console.error('CSRF token not found');
                showToast(helpTextTranslations['csrf_error'], 'danger');
                return;
            }

            const formData = new FormData();
            formData.append('action', 'edit_item');
            formData.append('item_id', newItem.id);
            formData.append('edit_item_name', newItem.name);
            formData.append('edit_item_quantity', newItem.quantity);
            formData.append('edit_item_price', newItem.price);
            formData.append('edit_item_unit', newItem.unit);
            formData.append('edit_item_category', newItem.category);
            formData.append('edit_item_status', newItem.status);
            formData.append('edit_item_store', newItem.store);
            formData.append('edit_item_frequency', newItem.frequency);
            formData.append('csrf_token', csrfToken);

            fetch(form.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrfToken
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    showToast(data.error || helpTextTranslations['edit_item_error'], 'danger');
                }
            })
            .catch(error => {
                console.error('Error saving edited item:', error);
                showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : helpTextTranslations['edit_item_error'], 'danger');
            });

            bootstrap.Modal.getInstance(document.getElementById('editItemModal'))?.hide();
        } catch (error) {
            console.error('Error saving edited item:', error);
            showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : helpTextTranslations['edit_item_error'], 'danger');
        }
    });

    // Delete item
    window.deleteItem = function(id) {
        try {
            const form = document.querySelector(`form.delete-item-form input[name="item_id"][value="${id}"]`)?.closest('form');
            if (!form) {
                console.error('Delete form not found for item:', id);
                showToast(helpTextTranslations['delete_item_error'], 'danger');
                return;
            }

            const csrfToken = form.querySelector('input[name="csrf_token"]')?.value || window.CSRF_TOKEN || '';
            if (!csrfToken) {
                console.error('CSRF token not found');
                showToast(helpTextTranslations['csrf_error'], 'danger');
                return;
            }

            const formData = new FormData(form);
            fetch(form.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRF-Token': csrfToken
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.reload();
                } else {
                    showToast(data.error || helpTextTranslations['delete_item_error'], 'danger');
                }
            })
            .catch(error => {
                console.error('Error deleting item:', error);
                showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : helpTextTranslations['delete_item_error'], 'danger');
            });
        } catch (error) {
            console.error('Error deleting item:', error);
            showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : helpTextTranslations['delete_item_error'], 'danger');
        }
    };

    // Add item
    document.getElementById('addItemSubmit')?.addEventListener('click', function() {
        const form = document.getElementById('addItemForm');
        if (!form) {
            console.error('Add item form not found');
            showToast("Form not found. Please try again.", 'danger');
            return;
        }

        let formIsValid = true;
        form.querySelectorAll('[required]').forEach(input => {
            if (!input.value.trim()) {
                input.classList.add('is-invalid');
                const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling : input.nextElementSibling?.nextElementSibling;
                if (helpElement) {
                    helpElement.innerText = input.id.includes('name')
                        ? helpTextTranslations['name_required']
                        : helpTextTranslations['budget_required'];
                }
                formIsValid = false;
            } else {
                input.classList.remove('is-invalid');
                const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling.nextElementSibling : input.nextElementSibling;
                if (helpElement) {
                    helpElement.innerText = helpTextTranslations[input.id.replace('item-', '')] || helpTextTranslations['name'];
                }
            }
        });

        form.querySelectorAll('.number-input').forEach(input => {
            const isInteger = input.id.includes('quantity') || input.id.includes('frequency');
            const allowCommas = input.dataset.allowCommas === 'true';
            let rawValue = cleanForParse(input.value);
            let numValue = isInteger ? parseInt(rawValue) || 0 : parseFloat(rawValue) || 0;
            const helpElement = input.nextElementSibling?.classList.contains('invalid-feedback') ? input.nextElementSibling.nextElementSibling : input.nextElementSibling;

            if (isInteger) {
                if (input.id.includes('quantity') && numValue > 1000) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['quantity_max'];
                    formIsValid = false;
                } else if (input.id.includes('frequency') && numValue > 365) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['frequency_max'];
                    formIsValid = false;
                } else if (numValue <= 0 && input.hasAttribute('required')) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                    formIsValid = false;
                } else {
                    input.classList.remove('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations[input.id.replace('item-', '')] || helpTextTranslations['quantity'] || helpTextTranslations['frequency'];
                }
            } else {
                if (!rawValue && input.hasAttribute('required')) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                    formIsValid = false;
                } else if (isNaN(numValue) && input.hasAttribute('required')) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['budget_required'];
                    formIsValid = false;
                } else if (numValue > 10000000000) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['amount_max'];
                    formIsValid = false;
                } else if (numValue <= 0 && input.hasAttribute('required')) {
                    input.classList.add('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations['amount_positive'];
                    formIsValid = false;
                } else {
                    input.classList.remove('is-invalid');
                    if (helpElement) helpElement.innerText = helpTextTranslations[input.id.replace('item-', '')] || helpTextTranslations['price'];
                }
            }
            input.value = isInteger ? numValue.toString() : (allowCommas && !isNaN(numValue) ? formatForDisplay(numValue, false) : (isNaN(numValue) ? '' : numValue.toFixed(2)));
        });

        if (!formIsValid) {
            const firstInvalid = form.querySelector('.is-invalid');
            if (firstInvalid) {
                firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                firstInvalid.focus();
            }
            return;
        }

        const csrfToken = form.querySelector('input[name="csrf_token"]')?.value || window.CSRF_TOKEN || '';
        if (!csrfToken) {
            console.error('CSRF token not found');
            showToast(helpTextTranslations['csrf_error'], 'danger');
            return;
        }

        const formData = new FormData(form);
        formData.set('item_price', cleanForParse(form.querySelector('#item_price').value));
        formData.set('item_quantity', parseInt(form.querySelector('#item_quantity').value) || 1);
        formData.set('item_frequency', parseInt(form.querySelector('#item_frequency').value) || 1);

        const submitButton = this;
        submitButton.disabled = true;
        const spinner = submitButton.querySelector('.spinner-border') || document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm';
        spinner.setAttribute('role', 'status');
        spinner.setAttribute('aria-hidden', 'true');
        if (!submitButton.contains(spinner)) submitButton.prepend(spinner);
        const icon = submitButton.querySelector('i');
        if (icon) icon.classList.add('d-none');

        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRF-Token': csrfToken
            }
        })
        .then(response => response.json())
        .then(data => {
            submitButton.disabled = false;
            spinner.remove();
            if (icon) icon.classList.remove('d-none');

            if (data.success) {
                showToast(helpTextTranslations['item_added'], 'success');
                updateItemsTable(data.item);
                form.reset();
                updateBudgetProgress(form);
                const itemAddedToast = document.getElementById('itemAddedToast');
                if (itemAddedToast) {
                    itemAddedToast.classList.remove('d-none');
                    new bootstrap.Toast(itemAddedToast).show();
                }
            } else {
                showToast(data.error || helpTextTranslations['add_item_error'], 'danger');
            }
        })
        .catch(error => {
            submitButton.disabled = false;
            spinner.remove();
            if (icon) icon.classList.remove('d-none');
            console.error('Error adding item:', error);
            showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : helpTextTranslations['add_item_error'], 'danger');
        });
    });

    // Update items table dynamically
    function updateItemsTable(item) {
        const tbody = document.getElementById('items-table-body');
        if (!tbody) {
            console.warn('Items table body not found');
            return;
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${item.name}</td>
            <td>${item.quantity}</td>
            <td>${formatForDisplay(item.price, false)}</td>
            <td>${item.unit}</td>
            <td>${item.category}</td>
            <td>${item.status}</td>
            <td>${item.store || ''}</td>
            <td>${item.frequency || ''}</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="openEditModal('${item.id}', '${item.name}', ${item.quantity}, ${item.price}, '${item.unit}', '${item.category}', '${item.status}', '${item.store || ''}', ${item.frequency || 1})">
                    <i class="fa-solid fa-edit"></i>
                </button>
                <form class="delete-item-form d-inline" method="POST" action="${document.getElementById('addItemForm').action}">
                    <input type="hidden" name="csrf_token" value="${window.CSRF_TOKEN}">
                    <input type="hidden" name="action" value="delete_item">
                    <input type="hidden" name="item_id" value="${item.id}">
                    <button type="submit" class="btn btn-sm btn-danger" onclick="deleteItem('${item.id}'); return false;">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </form>
            </td>
        `;
        tbody.prepend(row);
        initializeNumberInputs();
    }

    // Calculate total cost for manage list form
    function calculateTotalCost(form) {
        try {
            if (!form) return 0;
            let total = 0;
            form.querySelectorAll('.new-item-quantity').forEach((quantityInput, index) => {
                const priceInput = form.querySelectorAll('.new-item-price')[index];
                const nameInput = form.querySelectorAll('.new-item-name')[index];
                if (nameInput?.value.trim()) {
                    const quantity = parseInt(quantityInput.value) || 0;
                    const price = parseFloat(cleanForParse(priceInput.value)) || 0;
                    total += quantity * price;
                }
            });
            const totalSpentElement = form.querySelector('#total-spent') || document.getElementById('total-spent');
            const totalSpentRaw = parseFloat(cleanForParse(totalSpentElement?.textContent)) || 0;
            return total + totalSpentRaw;
        } catch (error) {
            console.error('Error calculating total cost:', error);
            return 0;
        }
    }

    // Update budget progress
    function updateBudgetProgress(form) {
        if (!form) return;
        try {
            const total = calculateTotalCost(form);
            const budgetInput = form.querySelector('#list_budget');
            const budget = budgetInput ? parseFloat(cleanForParse(budgetInput.value)) || 0 : 0;
            const progressBar = form.querySelector('#budget-progress') || document.getElementById('budget-progress');
            if (progressBar && budget > 0) {
                const percentage = Math.min((total / budget * 100).toFixed(2), 100);
                progressBar.style.width = `${percentage}%`;
                progressBar.setAttribute('aria-valuenow', percentage);
            }
            const totalSpentElement = form.querySelector('#total-spent') || document.getElementById('total-spent');
            if (totalSpentElement) {
                totalSpentElement.textContent = formatForDisplay(total, false);
            }
            const remainingElement = form.querySelector('#remaining-budget') || document.getElementById('remaining-budget');
            if (remainingElement) {
                const remaining = budget - total;
                remainingElement.textContent = remaining >= 0
                    ? formatForDisplay(remaining, false)
                    : `Over by: ${formatForDisplay(-remaining, false)}`;
            }
            const budgetAmountElement = form.querySelector('#budget-amount') || document.getElementById('budget-amount');
            if (budgetAmountElement) {
                budgetAmountElement.textContent = formatForDisplay(budget, false);
            }
        } catch (error) {
            console.error('Error updating budget progress:', error);
        }
    }

    // Load list details via AJAX
    window.loadListDetails = function(listId, tab) {
        if (window.isAuthenticatedContentBlocked) {
            showToast('Please log in to perform this action.', 'danger');
            return;
        }
        const detailsDiv = document.getElementById(tab === 'manage-list' ? 'manage-list-details' : 'dashboard-content');
        if (!detailsDiv) {
            console.error('Details div not found for tab:', tab);
            showToast('Failed to load list details. Please try again.', 'danger');
            return;
        }

        if (!listId) {
            detailsDiv.innerHTML = `
                <div class="empty-state text-center">
                    <i class="fa-solid fa-cart-shopping fa-3x mb-3"></i>
                    <p>No active list selected. Please select an active list to manage.</p>
                    <a href="/personal/shopping?tab=create-list" class="btn btn-primary">
                        <i class="fa-solid fa-plus"></i> Create List
                    </a>
                </div>
            `;
            return;
        }

        detailsDiv.innerHTML = `
            <div class="text-center">
                <div class="spinner-border" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;

        fetch(window.SHOPPING_GET_LIST_DETAILS_URL + '?list_id=' + encodeURIComponent(listId) + '&tab=' + encodeURIComponent(tab), {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success && data.html) {
                detailsDiv.innerHTML = data.html;
                initializeNumberInputs();
                initializeFormValidation();
                updateBudgetProgress(document.getElementById('addItemsForm') || document.getElementById('updateListForm') || document.getElementById('saveListForm'));
                document.querySelectorAll('.toast').forEach(toast => {
                    new bootstrap.Toast(toast).show();
                });
            } else {
                detailsDiv.innerHTML = `
                    <div class="empty-state text-center">
                        <i class="fa-solid fa-exclamation-triangle fa-3x mb-3"></i>
                        <p>${data.error || "Failed to load list details. Please try again."}</p>
                        <a href="/personal/shopping?tab=create-list" class="btn btn-primary">
                            <i class="fa-solid fa-plus"></i> Create List
                        </a>
                    </div>
                `;
                showToast(data.error || "Failed to load list details. Please try again.", 'danger');
            }
        })
        .catch(error => {
            console.error('Error loading list details:', error);
            detailsDiv.innerHTML = `
                <div class="empty-state text-center">
                    <i class="fa-solid fa-exclamation-triangle fa-3x mb-3"></i>
                    <p>Failed to load list details. Please try again.</p>
                    <a href="/personal/shopping?tab=create-list" class="btn btn-primary">
                        <i class="fa-solid fa-plus"></i> Create List
                    </a>
                </div>
            `;
            showToast(error.message.includes('CSRF') ? helpTextTranslations['csrf_error'] : "Failed to load list details. Please try again.", 'danger');
        });
    };

    // Initialize tooltips
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(tooltipTriggerEl => {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Show toasts
    document.querySelectorAll('.toast').forEach(toast => {
        new bootstrap.Toast(toast).show();
    });

    // Initialize budget progress and form validation
    initializeNumberInputs();
    initializeFormValidation();

    // Trigger load if a list is pre-selected
    const manageSelect = document.getElementById('manage-list-select');
    if (manageSelect?.value) {
        loadListDetails(manageSelect.value, 'manage-list');
    } else if (manageSelect) {
        loadListDetails('', 'manage-list');
    }

    const dashboardSelect = document.getElementById('dashboard-list-select');
    if (dashboardSelect?.value) {
        loadListDetails(dashboardSelect.value, 'dashboard');
    }

    // Ensure items-table-body exists
    if (!document.getElementById('items-table-body')) {
        console.warn('items-table-body element not found. Initializing empty tbody.');
        const table = document.getElementById('items-table');
        if (table) {
            const tbody = document.createElement('tbody');
            tbody.id = 'items-table-body';
            table.appendChild(tbody);
        }
    }

    // Tab persistence with sessionStorage
    const activeTab = document.querySelector('.nav-link.active')?.id.replace('-tab', '');
    if (activeTab) {
        sessionStorage.setItem('activeShoppingTab', activeTab);
    }

    // Re-enable buttons on page load
    document.querySelectorAll('button[type="submit"]').forEach(button => {
        button.disabled = false;
        const spinner = button.querySelector('.spinner-border');
        if (spinner) spinner.classList.add('d-none');
        const icon = button.querySelector('i');
        if (icon) icon.classList.remove('d-none');
    });
});
